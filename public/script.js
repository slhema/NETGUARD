const loginForm = document.querySelector("form");

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.querySelector('input[type="email"]').value;
    const password = document.querySelector('input[type="password"]').value;

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        const data = await response.json();

        if (data.success) {

            // Store logged-in user information
            localStorage.setItem("netguardUser", JSON.stringify(data.user));

            // Open NETGUARD dashboard
            window.location.href = "/dashboard.html";

        } else {

            alert(data.message);

        }

    } catch (error) {

        console.error("Login error:", error);

        alert("Unable to connect to NETGUARD server.");

    }
});