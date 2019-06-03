package terradeployutils

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mongo "go.mongodb.org/mongo-driver/mongo"
)

// NSData represent a namespace
type NSData struct {
	ID      primitive.ObjectID `json:"_id,omitempty"`
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
	return owners, members
}

// isOwnerOfNS checks if user is owner of namespace
func IsOwnerOfNS(coll *mongo.Collection, ns string, uid string) bool {
	owners, _ := _getNS(coll, ns)
	for _, owner := range owners {
		if owner == uid {
			return true
		}
	}
	return false
}

// isMemberOfNS checks if user is owner or member of namespace
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
