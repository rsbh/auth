package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"
	"github.com/rsbh/auth/models"
)

func main() {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatalf("error: enforcer: %s", err)
	}

	user := models.User{uuid.New(), "Test User"}
	resource := models.Resource{uuid.New(), "Test Resource"}
	group := models.Group{uuid.New(), "Test Group"}

	// AddPolicy: Subject, Resource, Relationship, Action
	e.AddPolicy(user.GetId(), resource.GetId(), models.GetRelation(user, resource), "read")
	e.AddPolicy(group.GetId(), resource.GetId(), models.GetRelation(group, resource), "read")
	e.SavePolicy()

	ok, err := e.Enforce(user.GetId(), resource.GetId(), "user:resource", "read")

	if err != nil {
		log.Fatalf("error: Enforce: %s", err)
	}

	fmt.Println(ok)
}
