document.addEventListener("DOMContentLoaded", () => {
    const authToken = localStorage.getItem("authToken");

    if (!authToken) {
        alert("No token found. Please log in.");
        window.location.href = "/login.html"; // Перенаправляем на страницу логина
        return;
    }

    // Проверяем доступ к управлению
    fetch("/management", {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${authToken}`,
        },
    })
        .then((response) => {
            if (response.ok) {
                return response.text();
            } else {
                throw new Error("Unauthorized");
            }
        })
        .then((data) => {
            document.body.innerHTML = data; // Отображаем контент страницы
            loadUsers(); // Загружаем список пользователей
        })
        .catch((err) => {
            alert("Access denied: " + err.message);
            window.location.href = "/login.html"; // Перенаправляем на логин
        });
});

// Функция для загрузки пользователей
async function loadUsers() {
    const authToken = localStorage.getItem("authToken");

    try {
        const response = await fetch("/management/users", {
            headers: { Authorization: `Bearer ${authToken}` },
        });

        if (response.ok) {
            const users = await response.json();
            const usersContent = document.getElementById("users-content");
            usersContent.innerHTML = `
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${users
                .map(
                    (user) => `
                                <tr>
                                    <td>${user.id}</td>
                                    <td>${user.name}</td>
                                    <td>${user.email}</td>
                                    <td>${user.role}</td>
                                    <td>
                                        <button onclick="editUser(${user.id})">Edit</button>
                                        <button onclick="deleteUser(${user.id})">Delete</button>
                                    </td>
                                </tr>
                            `
                )
                .join("")}
                    </tbody>
                </table>
            `;
        } else {
            throw new Error("Failed to load users");
        }
    } catch (err) {
        console.error(err);
        alert("Failed to load users");
    }
}

// Функция для входа
async function login() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    const response = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem("authToken", data.token);
        alert("Login successful!");
        window.location.href = "/management";
    } else {
        alert("Login failed!");
    }
}

// Функция редактирования пользователя
async function editUser(userId) {
    const newRole = prompt("Enter new role for user (e.g., 'admin', 'manager', 'user'):");
    if (!newRole) {
        return;
    }

    const authToken = localStorage.getItem("authToken");
    try {
        const response = await fetch(`/management/users/${userId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`,
            },
            body: JSON.stringify({ role: newRole }),
        });

        if (response.ok) {
            alert("User updated successfully");
            loadUsers(); // Обновляем список пользователей
        } else {
            throw new Error("Failed to update user");
        }
    } catch (err) {
        console.error(err);
        alert("Error updating user");
    }
}

// Функция удаления пользователя
async function deleteUser(userId) {
    const confirmation = confirm("Are you sure you want to delete this user?");
    if (!confirmation) {
        return;
    }

    const authToken = localStorage.getItem("authToken");
    try {
        const response = await fetch(`/management/users/${userId}`, {
            method: "DELETE",
            headers: {
                "Authorization": `Bearer ${authToken}`,
            },
        });

        if (response.ok) {
            alert("User deleted successfully");
            loadUsers(); // Обновляем список пользователей
        } else {
            throw new Error("Failed to delete user");
        }
    } catch (err) {
        console.error(err);
        alert("Error deleting user");
    }
}
