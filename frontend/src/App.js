
import React from "react";

import Hero from "./components/sections/Hero";
import QuemSomos from "./components/pages/QuemSomos";
import ComoFunciona from "./components/pages/ComoFunciona";
import Layout from "./components/layout/Layout";
import Login from "./components/pages/Login";
import Cadastro from "./components/pages/Cadastro";
import Dashboard from "./components/pages/Dashboard";
import Perfil from "./components/pages/Perfil";
import PrivateRoute from "./components/PrivateRoutes";

import {
  BrowserRouter as Router,
  Routes,
  Route
} from "react-router-dom";

function App() {
  return (
    <Router>
      <Routes>

        {/* ROTA INICIAL COM LAYOUT */}
        <Route element={<Layout />}>
          <Route path="/" element={<Hero />} />
        </Route>

        {/* ROTAS PÚBLICAS */}
        <Route
          path="/quem-somos"
          element={<QuemSomos />}
        />

        <Route
          path="/comoFunciona"
          element={<ComoFunciona />}
        />

        <Route
          path="/login"
          element={<Login />}
        />

        <Route
          path="/cadastro"
          element={<Cadastro />}
        />

        {/* ROTA PRIVADA - DASHBOARD */}
        <Route
          path="/dashboard"
          element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          }
        />

        {/* ROTA PRIVADA - PERFIL */}
        <Route
          path="/perfil"
          element={
            <PrivateRoute>
              <Perfil />
            </PrivateRoute>
          }
        />

      </Routes>
    </Router>
  );
}

export default App;
