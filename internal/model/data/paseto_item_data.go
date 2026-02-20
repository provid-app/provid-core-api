package data

import "aidanwoods.dev/go-paseto"

type PasetoItemData struct {
	PasetoSecret *paseto.V4AsymmetricSecretKey
	PasetoPublic *paseto.V4AsymmetricPublicKey
}
