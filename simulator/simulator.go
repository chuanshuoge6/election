package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://bob:password@cluster0.yvyo2.mongodb.net/test?retryWrites=true&w=majority"))
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 100*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	electionDatabase := client.Database("sample_election")
	votersCollection := electionDatabase.Collection("voters")

	cost := bcrypt.DefaultCost
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("abc"), cost)

	for i := 0; i < 100; i++ {
		var ballot = ""
		randomN := rand.Intn(100)
		if randomN > 50 {
			ballot = "humanoid"
		} else {
			ballot = "human"
		}

		address, err := votersCollection.InsertOne(ctx, bson.D{
			{"user", strconv.Itoa(i)},
			{"password", hashedPassword},
			{"ballot", ballot},
		})
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("inserted", strconv.Itoa(i), "@ ", address)
	}
}
