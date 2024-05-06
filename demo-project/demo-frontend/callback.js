// get the id_token and refresh_token from the fragment part of the url
// and store them in the session storage
const params = new URLSearchParams(window.location.hash.slice(1));
const idToken = params.get('id_token');
const refreshToken = params.get('refresh_token');
const state = params.get('state');
const code = params.get('code');

const insertText = (text, tag = 'h2') => {
  const el = document.createElement(tag);
  el.innerText = text;
  document.body.appendChild(el);
};

const accessProtectedRoute = (token, cb = null) => {
  // use token to access protected route
  fetch('/protected', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  })
    .then((resp) => {
      if (resp.status == 200) {
        resp.text().then((data) => {
          insertText(data);
          if (cb) cb();
        });
      } else {
        insertText(`Error: ${resp.status} ${resp.statusText}`);
      }
    })
    .catch((error) => {
      insertText(`Error: ${error}`);
    });
};

const accessProtectedRouteWithTokenFrom = (endpoint, data, cb = null) => {
  fetch(`http://localhost:3001${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
    .then((resp) => {
      if (resp.status == 200) {
        resp.json().then((data) => {
          insertText(`access_token: ${data.accessToken}`, 'h4');
          insertText(`refresh_token: ${data.refreshToken}`, 'h4');

          accessProtectedRoute(data.accessToken, () => {
            if (cb) cb(data);
          });
        });
      } else {
        resp.text().then((data) => {
          insertText(`Error: ${resp.status} ${resp.statusText} -- ${data}`);
        });
      }
    })
    .catch((error) => {
      insertText(`Error: ${error}`);
    });
};

if (idToken && refreshToken && state) {
  accessProtectedRoute(idToken);
  document.getElementById('client-secret-input').style.display = 'none';
} else if (code) {
  const clientId = document.getElementById('client-id').value;
  const clientSecret = document.getElementById('client-secret').value;

  // fetch access_token and refresh_token
  accessProtectedRouteWithTokenFrom(
    '/api/v1/token',
    {
      grantType: 'authorization_code',
      code,
      redirectUri: 'http://localhost:1606/callback.html',
      clientId,
      clientSecret,
    },
    (data) => {
      insertText('Refreshing token...', 'h4');

      // refresh token to get a new access token (in order to test refresh functionality)
      accessProtectedRouteWithTokenFrom('/api/v1/refresh', {
        refreshToken: data.refreshToken,
      });
    },
  );
}
