// get the id_token and refresh_token from the fragment part of the url
// and store them in the session storage
const params = new URLSearchParams(window.location.hash.slice(1));
const idToken = params.get("id_token");
const refreshToken = params.get("refresh_token");
const state = params.get("state");
const code = params.get("code");

console.log("idToken", idToken);
console.log("refreshToken", refreshToken);
console.log("state", state);
console.log("code", code);

const accessProtectedRoute = async (token) => {
    // use token to access protected route
    const resp = await fetch("/protected", {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    });
    const greeting = document.createElement("h2");
    if (resp.status !== 200) {
        greeting.innerText = `Error: ${resp.status} ${resp.statusText}`;
        document.body.appendChild(greeting);
        return;
    }
    greeting.innerText = await resp.text();
    document.body.appendChild(greeting);
};

if (idToken && refreshToken && state) {
    accessProtectedRoute(idToken);
} else if (code) {
    const clientId = document.getElementById("client-id").value;
    const clientSecret = document.getElementById("client-secret").value;

    const fn = async () => {
        await fetch("http://localhost:3001/api/v1/token", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                grantType: "authorization_code",
                code,
                redirectUri: "http://localhost:1606/callback.html",
                clientId: clientId,
                clientSecret: clientSecret,
            }),
        })
            .then((resp) => resp.json())
            .then(async (data) => {
                accessProtectedRoute(data.accessToken);
            });
    };

    fn();
}
