package main

import (
	"os"
	"testing"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

func TestUserRegistrationE2E(t *testing.T) {
	// Установка переменной окружения для тестовой среды
	os.Setenv("ENV", "test")
	t.Log("Running in test environment")

	// Настройки WebDriver
	caps := selenium.Capabilities{"browserName": "chrome"}
	chromeCaps := chrome.Capabilities{
		Args: []string{"--disable-gpu", "--no-sandbox", "--disable-popup-blocking"},
	}
	caps.AddChrome(chromeCaps)

	// Подключение к WebDriver
	wd, err := selenium.NewRemote(caps, "http://localhost:4455")
	if err != nil {
		t.Fatalf("Failed to connect to WebDriver: %v", err)
	}
	defer wd.Quit()

	// Открытие страницы регистрации
	t.Log("Opening registration page")
	err = wd.Get("http://localhost:8080/register.html")
	if err != nil {
		t.Fatalf("Failed to load registration.html: %v", err)
	}

	// Заполнение формы регистрации
	t.Log("Filling out the registration form")
	nameField, err := wd.FindElement(selenium.ByID, "name")
	if err != nil {
		t.Fatalf("Failed to find name field: %v", err)
	}
	nameField.SendKeys("Test User")

	emailField, err := wd.FindElement(selenium.ByID, "email")
	if err != nil {
		t.Fatalf("Failed to find email field: %v", err)
	}
	emailField.SendKeys("test.user@example.com")

	passwordField, err := wd.FindElement(selenium.ByID, "password")
	if err != nil {
		t.Fatalf("Failed to find password field: %v", err)
	}
	passwordField.SendKeys("testpassword")

	registerButton, err := wd.FindElement(selenium.ByID, "register-btn")
	if err != nil {
		t.Fatalf("Failed to find register button: %v", err)
	}
	registerButton.Click()

	// Ожидание сообщения об успешной регистрации
	t.Log("Waiting for confirmation message")
	time.Sleep(2 * time.Second)

	// Принудительное закрытие алертов, если они появляются
	alertText, err := wd.AlertText()
	if err == nil {
		t.Logf("Unexpected alert found and accepted: %s", alertText)
		wd.AcceptAlert() // Закрыть алерт
		time.Sleep(1 * time.Second)
	}

	// Поиск элемента с сообщением об успехе
	confirmationMessage, err := wd.FindElement(selenium.ByID, "success-message")
	if err != nil {
		t.Fatalf("Failed to find confirmation message: %v", err)
	}

	text, err := confirmationMessage.Text()
	if err != nil {
		t.Fatalf("Failed to retrieve text from confirmation message: %v", err)
	}

	expectedMessage := "Registration successful! Please check your email to verify your account."
	if text != expectedMessage {
		t.Errorf("Unexpected confirmation message. Got: %s, expected: %s", text, expectedMessage)
	} else {
		t.Log("Registration test passed successfully")
	}
}
