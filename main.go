package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"
)

type User struct {
	Id   uuid.UUID
	Name string
}

type Resource struct {
	Id   uuid.UUID
	Name string
}

func (u User) getId() string {
	return u.Id.String()
}

func (r Resource) getId() string {
	return r.Id.String()
}

func main() {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatalf("error: enforcer: %s", err)
	}

	user := User{uuid.New(), "Test User"}
	resource := Resource{uuid.New(), "Test Resource"}

	// AddPolicy: Subject, Resource, Relationship, Action
	e.AddPolicy(user.getId(), resource.getId(), "user:resource", "read")
	e.SavePolicy()

	ok, err := e.Enforce(user.getId(), resource.getId(), "user:resource", "read")

	if err != nil {
		log.Fatalf("error: Enforce: %s", err)
	}

	fmt.Println(ok)
}
