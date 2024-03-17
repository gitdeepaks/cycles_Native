const messageTag = document.getElementById("message");

window.addEventListener("DOMContentLoaded", async () => {
  const params = new Proxy(new URLSearchParams(window.location.search), {
    get: (searchParams, prop) => searchParams.get(prop),
  });
  const token = params.token;
  const id = params.id;

  try {
    const res = await fetch(`/auth/verify/`, {
      method: "POST",
      body: JSON.stringify({ token, id }),
      headers: {
        "Content-Type": "application/json;charset=utf-8",
      },
    });

    const data = await res.json(); // Read the JSON once here

    if (!res.ok) {
      messageTag.innerText = data.message; // Use the parsed JSON
      messageTag.classList.add("error");
      return;
    }

    messageTag.innerText = data.message; // Use the same parsed JSON for success path
  } catch (error) {
    // Handle network error or JSON parsing error
    messageTag.innerText = "An error occurred while processing your request.";
    messageTag.classList.add("error");
  }
});
