import { useState } from "react";
import axios from "axios";

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const login = async () => {

    try {

      const response = await axios.post(
        "http://127.0.0.1:5000/api/login",
        {
          username,
          password,
        }
      );

      if (response.data.success) {

        localStorage.setItem("token", response.data.token);
        localStorage.setItem("loggedIn", "true");

        onLogin();

      } else {

        setError("Invalid Username or Password");

      }

    } catch (err) {

      console.error(err);
      setError("Login Failed");

    }

  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      login();
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">

        <h1>Smart NIDS</h1>

        <p>Network Intrusion Detection System</p>

        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          onKeyDown={handleKeyDown}
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={handleKeyDown}
        />

        <button onClick={login}>
          Login
        </button>

        {error && (
          <p className="login-error">
            {error}
          </p>
        )}

      </div>
    </div>
  );
}

export default Login;
