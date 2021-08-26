package models

import (
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

func (g Group) GetType() string {
	return "group"
}

func (u User) GetType() string {
	return "user"
}

func (r Resource) GetType() string {
	return "resource"
}

func (p Project) GetType() string {
	return "project"
}
