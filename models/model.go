package models

import (
	"fmt"

	"github.com/google/uuid"
)

type User struct {
	Id    uuid.UUID
	Name  string
	Email string
}

type Resource struct {
	Id   uuid.UUID
	Name string
}

type Group struct {
	Id   uuid.UUID
	Name string
}

type Project struct {
	Id   uuid.UUID
	Name string
}

func (g Group) GetId() string {
	return g.Id.String()
}

func (u User) GetId() string {
	return u.Id.String()
}

func (r Resource) GetId() string {
	return r.Id.String()
}

func (p Project) GetId() string {
	return p.Id.String()
}

func getType(i interface{}) string {
	switch i.(type) {
	case User:
		return "user"
	case Resource:
		return "resource"
	case Group:
		return "group"
	default:
		return ""
	}
}

func GetRelation(i interface{}, j interface{}) string {
	itype := getType(i)
	jtype := getType(j)

	return fmt.Sprintf("%s:%s", itype, jtype)
}
