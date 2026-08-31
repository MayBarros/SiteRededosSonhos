
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/Perfil.css";

function Perfil() {
  const navigate = useNavigate();

  const user = JSON.parse(localStorage.getItem("user")) || {};

  // Controla o modo de edição
  const [editando, setEditando] = useState(false);

  // Dados do usuário
  const [formData, setFormData] = useState({
    nome: user.nome || "",
    email: user.email || "",
    telefone: user.telefone || "",
    status: user.status || ""
  });

  // Foto do usuário
  const [foto, setFoto] = useState(user.foto || null);

  // Mensagem de retorno
  const [mensagem, setMensagem] = useState("");

  // Guarda os dados originais para o botão cancelar
  const [dadosOriginais, setDadosOriginais] = useState({
    nome: user.nome || "",
    email: user.email || "",
    telefone: user.telefone || "",
    status: user.status || ""
  });

  const [fotoOriginal, setFotoOriginal] = useState(
    user.foto || null
  );


  // ========================================
  // ALTERAR CAMPOS
  // ========================================

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData({
      ...formData,
      [name]: value
    });

    setMensagem("");
  };


  // ========================================
  // ALTERAR FOTO
  // ========================================

  const handleFoto = (e) => {
    const file = e.target.files[0];

    if (!file) {
      return;
    }

    // Verifica se o arquivo é uma imagem
    if (!file.type.startsWith("image/")) {
      setMensagem("Selecione uma imagem válida.");
      return;
    }

    // Limita o tamanho da imagem para 5 MB
    if (file.size > 5 * 1024 * 1024) {
      setMensagem("A imagem deve ter no máximo 5 MB.");
      return;
    }

    // Cria a imagem para visualização
    const reader = new FileReader();

    reader.onloadend = () => {
      setFoto(reader.result);
    };

    reader.readAsDataURL(file);

    setMensagem("");
  };


  // ========================================
  // ENTRAR NO MODO DE EDIÇÃO
  // ========================================

  const handleEditar = () => {

    // Guarda os dados atuais
    setDadosOriginais({
      nome: formData.nome,
      email: formData.email,
      telefone: formData.telefone,
      status: formData.status
    });

    setFotoOriginal(foto);

    setMensagem("");

    setEditando(true);
  };


  // ========================================
  // CANCELAR EDIÇÃO
  // ========================================

  const handleCancelar = () => {

    setFormData({
      nome: dadosOriginais.nome,
      email: dadosOriginais.email,
      telefone: dadosOriginais.telefone,
      status: dadosOriginais.status
    });

    setFoto(fotoOriginal);

    setMensagem("");

    setEditando(false);
  };


  // ========================================
  // SALVAR ALTERAÇÕES
  // ========================================

  const handleSalvar = (e) => {
    e.preventDefault();

    // Validação
    if (!formData.nome.trim()) {
      setMensagem("O nome é obrigatório.");
      return;
    }

    if (!formData.email.trim()) {
      setMensagem("O e-mail é obrigatório.");
      return;
    }

    /*
      Por enquanto estamos salvando no localStorage.

      Depois podemos substituir esta parte por uma
      requisição PUT para o backend.
    */

    const updatedUser = {
      ...user,

      nome: formData.nome,
      email: formData.email,
      telefone: formData.telefone,
      status: formData.status,
      foto: foto
    };

    localStorage.setItem(
      "user",
      JSON.stringify(updatedUser)
    );

    // Atualiza os dados originais
    setDadosOriginais({
      nome: formData.nome,
      email: formData.email,
      telefone: formData.telefone,
      status: formData.status
    });

    setFotoOriginal(foto);

    setMensagem("Perfil atualizado com sucesso!");

    setEditando(false);
  };


  return (
    <div className="perfil-page">

      <div className="perfil-container">

        {/* ====================================
            CABEÇALHO DO PERFIL
        ==================================== */}

        <div className="perfil-header">

          <div className="perfil-photo-area">

            {foto ? (
              <img
                src={foto}
                alt="Foto de perfil"
                className="perfil-photo"
              />
            ) : (
              <div className="perfil-avatar">
                {formData.nome
                  ? formData.nome
                      .charAt(0)
                      .toUpperCase()
                  : "U"}
              </div>
            )}

            {/* Alterar foto somente no modo edição */}

            {editando && (
              <>
                <label
                  htmlFor="foto"
                  className="alterar-foto"
                >
                  📷 Alterar foto
                </label>

                <input
                  id="foto"
                  type="file"
                  accept="image/*"
                  onChange={handleFoto}
                  hidden
                />
              </>
            )}

          </div>


          <div className="perfil-header-info">

            <h1>
              {formData.nome || "Usuário"}
            </h1>

            <p className="perfil-status">
              {formData.status ||
                "Ainda não definiu um status."}
            </p>

          </div>

        </div>


        {/* ====================================
            CONTEÚDO
        ==================================== */}

        <div className="perfil-content">

          <div className="perfil-title-area">

            <div>

              <h2>Meu perfil</h2>

              <p>
                Veja e gerencie suas informações pessoais.
              </p>

            </div>


            {/* BOTÃO EDITAR */}

            {!editando && (
              <button
                type="button"
                className="btn-editar"
                onClick={handleEditar}
              >
                ✏️ Editar perfil
              </button>
            )}

          </div>


          {/* ====================================
              FORMULÁRIO
          ==================================== */}

          <form
            className="perfil-form"
            onSubmit={handleSalvar}
          >

            <div className="form-section">

              <h3>Informações pessoais</h3>


              {/* NOME */}

              <div className="form-group">

                <label>
                  Nome completo
                </label>

                {editando ? (
                  <input
                    type="text"
                    name="nome"
                    value={formData.nome}
                    onChange={handleChange}
                    placeholder="Digite seu nome"
                    required
                  />
                ) : (
                  <div className="info-value">
                    {formData.nome ||
                      "Não informado"}
                  </div>
                )}

              </div>


              {/* E-MAIL */}

              <div className="form-group">

                <label>
                  E-mail
                </label>

                {editando ? (
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Digite seu e-mail"
                    required
                  />
                ) : (
                  <div className="info-value">
                    {formData.email ||
                      "Não informado"}
                  </div>
                )}

              </div>


              {/* TELEFONE */}

              <div className="form-group">

                <label>
                  Telefone
                </label>

                {editando ? (
                  <input
                    type="tel"
                    name="telefone"
                    value={formData.telefone}
                    onChange={handleChange}
                    placeholder="(00) 00000-0000"
                  />
                ) : (
                  <div className="info-value">
                    {formData.telefone ||
                      "Não informado"}
                  </div>
                )}

              </div>


              {/* STATUS */}

              <div className="form-group">

                <label>
                  Status
                </label>

                {editando ? (
                  <textarea
                    name="status"
                    value={formData.status}
                    onChange={handleChange}
                    placeholder="Escreva algo sobre você..."
                    maxLength={150}
                    rows={3}
                  />
                ) : (
                  <div className="info-value status-value">
                    {formData.status ||
                      "Ainda não definiu um status."}
                  </div>
                )}

              </div>

            </div>


            {/* ====================================
                MENSAGEM
            ==================================== */}

            {mensagem && (
              <div className="perfil-mensagem">
                {mensagem}
              </div>
            )}


            {/* ====================================
                BOTÕES
            ==================================== */}

            {editando && (
              <div className="perfil-actions">

                <button
                  type="button"
                  className="btn-cancelar"
                  onClick={handleCancelar}
                >
                  Cancelar
                </button>

                <button
                  type="submit"
                  className="btn-salvar"
                >
                  Salvar alterações
                </button>

              </div>
            )}

          </form>


          {/* ====================================
              VOLTAR
          ==================================== */}

          <button
            type="button"
            className="btn-voltar"
            onClick={() => navigate("/dashboard")}
          >
            ← Voltar para o início
          </button>

        </div>

      </div>

    </div>
  );
}

export default Perfil;

