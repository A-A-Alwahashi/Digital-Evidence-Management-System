const loginForm = document.getElementById("loginForm");
const message = document.getElementById("message");

loginForm.addEventListener("submit", async function (event) {
  event.preventDefault();

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

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
      message.textContent = "Login successful";
      message.style.color = "green";

      setTimeout(function () {
        window.location.href = "/dashboard";
      }, 500);
    } else {
      message.textContent = data.error || "Invalid username or password";

      message.style.color = "red";
    }
  } catch (error) {
    message.textContent = "Unable to connect to server";
    message.style.color = "red";
  }
});
