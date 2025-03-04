window.onload = async () => {
  try {
    const response = await fetch("/auth/home");

    if (response.status === 403) {
      document.body.innerHTML = `
            <div style="
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              flex-direction: column;
              background-color: #f8f9fa;
              font-family: Arial, sans-serif;
              color: #333;
            ">
              <div style="
                text-align: center;
                max-width: 600px;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
                background-color: #fff;
              ">
                <h1 style="font-size: 3rem; color: #dc3545;">403 Forbidden</h1>
                <p style="font-size: 1.25rem; margin-top: 15px;">
                  You are not signed in. Please sign in to access this page.
                </p>
                <button onclick="redirectToLogin()" style="
                  margin-top: 20px;
                  padding: 10px 20px;
                  font-size: 1rem;
                  background-color: #007bff;
                  color: #fff;
                  border: none;
                  border-radius: 5px;
                  cursor: pointer;
                  transition: background-color 0.3s;
                "
                onmouseover="this.style.backgroundColor='#0056b3'"
                onmouseout="this.style.backgroundColor='#007bff'">
                  Quay lại trang đăng nhập
                </button>
              </div>
            </div>
          `;

      return;
    }

    const message = await response.text();
    document.getElementById("welcomeMessage").innerText = message;

    document
      .querySelector("a[href='/index.html']")
      ?.addEventListener("click", handleLogout);
  } catch (error) {
    console.error("Error occurred:", error);
    redirectToLogin();
  }
};

async function handleLogout(event) {
  event.preventDefault();

  try {
    const response = await fetch("/auth/logout", {
      method: "POST",
    });

    if (response.ok) {
      window.location.href = "/index.html";
    } else {
      alert("Failed to log out. Please try again.");
    }
  } catch (error) {
    console.error("Error during logout:", error);
  }
}

function redirectToLogin() {
  window.location.href = "/index.html";
}
