// ==============================
// Login
// ==============================

const loginForm = document.getElementById("loginForm");

if (loginForm) {
  loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const message = document.getElementById("message");

    try {
      const response = await fetch("/auth/login", {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          username: username,
          password: password,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        message.className = "message success";
        message.textContent = "Login successful";

        localStorage.setItem("user_id", data.user_id);
        localStorage.setItem("role", data.role);
        localStorage.setItem("username", data.username);

        window.location.href = "/dashboard";
      } else {
        message.className = "message error";
        message.textContent = data.error || "Invalid username or password";
      }
    } catch (error) {
      message.className = "message error";
      message.textContent = "Unable to connect to server";
    }
  });
}

// ==============================
// Logout
// ==============================

function logout() {
  localStorage.removeItem("user_id");
  localStorage.removeItem("role");
  localStorage.removeItem("username");

  window.location.href = "/login";
}

// ==============================
// Display Username
// ==============================

const usernameElement = document.getElementById("usernameDisplay");

if (usernameElement) {
  const username = localStorage.getItem("username");

  if (username) {
    usernameElement.textContent = username;
  }
}

// ==============================
// Display User Role
// ==============================

const roleElement = document.getElementById("roleDisplay");

if (roleElement) {
  const role = localStorage.getItem("role");

  if (role) {
    roleElement.textContent = role;
  }
}
