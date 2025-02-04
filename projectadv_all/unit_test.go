package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateHashedPasswords(t *testing.T) {
	password := "password123"
	hashedPassword, err := generateHashedPasswords([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Error generating hashed password: %v", err)
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		t.Errorf("Generated hash does not match the original password")
	}
}
