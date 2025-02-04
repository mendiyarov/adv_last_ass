package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// cleanDatabase очищает таблицу users перед началом теста
func cleanDatabase() {
	if err := DB.Exec("DELETE FROM users").Error; err != nil {
		panic("Failed to clean database: " + err.Error())
	}
}

func TestCreateAndGetUser(t *testing.T) {
	// Подключение к базе данных
	connectDatabase()
	cleanDatabase() // Очистка базы перед тестом

	// Создаем пользователя через API
	user := map[string]string{
		"name":  "John Doe",
		"email": "john.doe@example.com",
	}
	body, _ := json.Marshal(user)

	req := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	createUserHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", w.Code)
	}

	// Логируем тело ответа для отладки
	t.Logf("Create user response: %s", w.Body.String())

	// Получаем всех пользователей через API
	req = httptest.NewRequest(http.MethodGet, "/users", nil)
	w = httptest.NewRecorder()
	getUsersHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	// Логируем тело ответа для отладки
	t.Logf("Get users response: %s", w.Body.String())

	var users []User
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatalf("Error unmarshalling response: %v", err)
	}

	if len(users) == 0 {
		t.Fatalf("No users found in response")
	}

	// Проверяем, что созданный пользователь есть в списке
	found := false
	for _, u := range users {
		if u.Email == "john.doe@example.com" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Created user not found in response")
	}
}
