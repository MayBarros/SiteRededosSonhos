import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/Login.css";

export default function Login() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: "",
    senha: ""
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch("http://localhost:5000/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem("token", data.token);
        localStorage.setItem("user", JSON.stringify(data.user));

        alert("Login realizado com sucesso!");
        navigate("/dashboard");
      } else {
        alert(data.message);
      }
    } catch (error) {
      console.error(error);
      alert("Erro ao conectar com o servidor.");
    }
  };

  return (
    <div className="login-container">

      <button className="back-button" onClick={() => navigate(-1)}>
        ⬅ Voltar
      </button>

      <div className="login-box">
        <h1 className="login-title">Rede dos Sonhos</h1>

        <form onSubmit={handleLogin}>
          <input
            type="email"
            name="email"
            placeholder="E-mail"
            className="login-input"
            onChange={handleChange}
            required
          />

          <input
            type="password"
            name="senha"
            placeholder="Senha"
            className="login-input"
            onChange={handleChange}
            required
          />

          <button type="submit" className="login-button">
            Entrar
          </button>
        </form>

        <div className="login-links">
          <span>Não tem conta? </span>

          <button
            onClick={() => navigate("/cadastro")}
            className="login-link cadastro-button"
          >
            Cadastre-se
          </button>
        </div>
      </div>
    </div>
  );
}