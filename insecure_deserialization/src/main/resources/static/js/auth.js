// register
document
  .getElementById("registerForm")
  ?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const messageElement = document.getElementById("registerMessage");

    const response = await fetch("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent(
        username
      )}&password=${encodeURIComponent(password)}`,
    });

    if (response.ok) {
      messageElement.textContent = "Registration successful!";
      messageElement.style.color = "green";

      setTimeout(() => {
        window.location.href = "/index.html";
      }, 1000);
    } else {
      messageElement.textContent = "Username already exists!";
      messageElement.style.color = "red";
    }
  });

// login
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const messageElement = document.getElementById("loginMessage");

  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `username=${encodeURIComponent(
      username
    )}&password=${encodeURIComponent(password)}`,
  });

  if (response.ok) {
    messageElement.textContent = "Login successful!";
    messageElement.style.color = "green";

    setTimeout(() => {
      window.location.href = "/home.html";
    }, 1000);
  } else {
    messageElement.textContent = "Invalid username or password!";
    messageElement.style.color = "red";
  }
});
