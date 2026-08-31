import React from 'react';
import '../styles/QuemSomos.css';
import imagemCentro from '../../assets/nuvemFundo.jpg';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';


function QuemSomos() {
  const handleVoltar = () => window.history.back();

  return (
    <div className="quem-somos">
      <button className="quem-somos-voltar" onClick={handleVoltar}>
        Voltar
      </button>

      <img
        src="https://cdn-icons-png.flaticon.com/512/1244/1244758.png"
        alt="Logo Rede dos Sonhos"
        className="quem-somos-logo"
      />

      <h1>Quem Somos</h1>
      <p>
        A Rede dos Sonhos é uma comunidade dedicada a conectar pessoas por meio
        da empatia, solidariedade e esperança. Nosso objetivo é criar pontes entre sonhos e aqueles que podem 
        torná-los realidade. Leia o regulamento e junte-se a nós.
      </p>
      
    </div>
  );
}


export default QuemSomos;
