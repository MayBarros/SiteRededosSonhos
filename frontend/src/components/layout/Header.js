import React from "react";
import "../styles/Header.css";
import { Link } from 'react-router-dom';


function Header() {
   return (
    <header className="header">
      <h1 className="logo">RedeDosSonhos</h1>
      <nav className="nav-buttons">
        <Link to="/quem-somos">
          <button>Quem é a rede dos sonhos</button>
        </Link>
        <Link to="/comoFunciona">
          <button>Como funciona</button>
        </Link>
        <Link to="/login" className="login-link"> Login
        </Link>
      </nav>
      
    </header>
  );
}

export default Header;
