package terradeployutils

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/streadway/amqp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mongo "go.mongodb.org/mongo-driver/mongo"

	terraConfig "github.com/osallou/goterra-lib/lib/config"
)

// NSData represent a namespace
type NSData struct {
	ID      primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name    string             `json:"name"`
	Owners  []string           `json:"owners"`
	Members []string           `json:"members"`
}

func _getNS(coll *mongo.Collection, nsID string) (owners []string, members []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	objID, _ := primitive.ObjectIDFromHex(nsID)
	ns := bson.M{
		"_id": objID,
	}

	var nsdb NSData
	err := coll.FindOne(ctx, ns).Decode(&nsdb)
	if err == mongo.ErrNoDocuments {
		return owners, members
	}
	return nsdb.Owners, nsdb.Members
}

// IsOwnerOfNS checks if user is owner of namespace
func IsOwnerOfNS(coll *mongo.Collection, ns string, uid string) bool {
	owners, _ := _getNS(coll, ns)
	for _, owner := range owners {
		if owner == uid {
			return true
		}
	}
	return false
}

// IsMemberOfNS checks if user is owner or member of namespace
func IsMemberOfNS(coll *mongo.Collection, ns string, uid string) bool {
	owners, members := _getNS(coll, ns)
	for _, owner := range owners {
		if owner == uid {
			return true
		}
	}
	for _, member := range members {
		if member == uid {
			return true
		}
	}
	return false
}

// RunAction is message struct to be sent to the run component
// action: apply or destroy
// id: identifier of the run
type RunAction struct {
	Action string `json:"action"`
	ID     string `json:"id"`
}

func sendRunAction(action string, id string) error {
	config := terraConfig.LoadConfig()
	if config.Amqp == "" {
		fmt.Printf("[ERROR] no amqp defined\n")
		return nil
	}
	conn, err := amqp.Dial(config.Amqp)
	if err != nil {
		fmt.Printf("[ERROR] failed to send %s for run %s\n", action, id)
		return err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		fmt.Printf("[ERROR] failed to connect to amqp\n")
		return err
	}

	err = ch.ExchangeDeclare(
		"gotrun", // name
		"fanout", // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	if err != nil {
		fmt.Printf("[ERROR] failed to connect to open exchange\n")
		return err
	}

	run := &RunAction{Action: action, ID: id}
	body, _ := json.Marshal(run)
	err = ch.Publish(
		"gotrun", // exchange
		"",       // routing key
		false,    // mandatory
		false,    // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	if err != nil {
		fmt.Printf("[ERROR] failed to send message\n")
		return err
	}
	return nil
}
