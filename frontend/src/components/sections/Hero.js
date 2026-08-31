import React from "react";
import "../styles/Hero.css";
import heroVideo from "../../assets/estrelado.mp4"; 
import { useNavigate } from "react-router-dom";

function Hero() {
  const navigate = useNavigate();

  return (
    <section className="hero">
      
      {/* Vídeo de fundo */}
      <video
        className="hero-video"
        autoPlay
        loop
        muted
        playsInline
      >
        <source src={heroVideo} type="video/mp4" />
      </video>

      <div className="hero-content">
        <h2>Compartilhe seu sonho. Realize o de alguém.</h2>
        <p>Uma rede que conecta sonhos a quem pode torná-los realidade.</p>

        <div className="hero-buttons">
          <button 
            className="btn primary" 
            onClick={() => navigate("/login")}
          >
            Quero Compartilhar
          </button>

          <button 
            className="btn secondary" 
            onClick={() => navigate("/login")}
          >
            Quero Ajudar
          </button>
        </div>
      </div>
    </section>
  );
}

export default Hero;