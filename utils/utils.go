package utils

import (
	"log"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/casbin/casbin/v2"
	"github.com/google/uuid"
	"github.com/rsbh/auth/models"
)

func NewEnforcer(model interface{}, policy interface{}) *casbin.Enforcer {
	e, err := casbin.NewEnforcer(model, policy)
	if err != nil {
		log.Fatalf("error: enforcer: %s", err)
	}
	return e
}

func NewUser() models.User {
	return models.User{Id: uuid.New(), Name: gofakeit.Name(), Email: gofakeit.Email()}
}

func NewResource() models.Resource {
	return models.Resource{Id: uuid.New(), Name: gofakeit.Name()}
}

func NewGroup() models.Group {
	return models.Group{Id: uuid.New(), Name: gofakeit.Name()}
}

func NewProject() models.Project {
	return models.Project{Id: uuid.New(), Name: gofakeit.Name()}
}

func NewWildCard(item Item) models.WildCard {
	return models.WildCard{Type: item.GetType()}
}

type Item interface {
	GetId() string
	GetType() string
}

func CreateUrn(items ...Item) string {
	var urn string
	for _, item := range items {
		urn += "/" + item.GetType() + "/" + item.GetId()
	}
	return urn
}
