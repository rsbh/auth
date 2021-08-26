package demo

import (
	"fmt"
	"log"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"
	"github.com/rsbh/auth/models"
)

func getEnforcer() *casbin.Enforcer {
	e, err := casbin.NewEnforcer("config/model.conf", "config/policy.csv")
	if err != nil {
		log.Fatalf("error: enforcer: %s", err)
	}
	return e
}

func newUser() models.User {
	return models.User{Id: uuid.New(), Name: gofakeit.Name(), Email: gofakeit.Email()}
}

func newResource() models.Resource {
	return models.Resource{Id: uuid.New(), Name: gofakeit.Name()}
}

func newGroup() models.Group {
	return models.Group{Id: uuid.New(), Name: gofakeit.Name()}
}

func newProject() models.Project {
	return models.Project{Id: uuid.New(), Name: gofakeit.Name()}
}

func getModels() (models.User, models.Resource, models.Group) {
	user := newUser()
	resource := newResource()
	group := newGroup()
	return user, resource, group
}

func Run() {
	p := newProject()
	e := getEnforcer()
	user, resource, group := getModels()
	user2, resource2, group2 := getModels()

	// AddPolicy: Subject, Resource, Domain, Action
	e.AddPolicy(group.GetId(), resource.GetId(), p.GetId(), "read")
	e.AddPolicy(group2.GetId(), resource2.GetId(), p.GetId(), "write")
	e.AddPolicy(group2.GetId(), resource2.GetId(), "*", "read")

	e.AddRoleForUser(user.GetId(), group.GetId(), p.GetId())
	e.AddRoleForUser(user2.GetId(), group2.GetId(), p.GetId())

	// e.AddRoleForUser(user.GetId(), fmt.Sprintf("%s-admin", resource.GetId()))

	e.SavePolicy()

	ok, err := e.Enforce(user.GetId(), resource.GetId(), p.GetId(), "write")

	if err != nil {
		log.Fatalf("error: Enforce: %s", err)
	}

	fmt.Println(ok)

	ok, err = e.Enforce(user2.GetId(), resource2.GetId(), p.GetId(), "write")
	if err != nil {
		log.Fatalf("error: Enforce: %s", err)
	}

	fmt.Println(ok)

	ok, err = e.Enforce(user2.GetId(), resource2.GetId(), "*", "read")
	if err != nil {
		log.Fatalf("error: Enforce: %s", err)
	}

	fmt.Println(ok)
}
