import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcrypt";

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

let db;

async function initDB() {
  db = await open({
    filename: "./usuarios.db",
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      senha TEXT NOT NULL,
      dataNascimento TEXT NOT NULL
    )
  `);

  console.log("Banco conectado");
}

initDB();


// ================= CADASTRO =================
app.post("/api/usuarios", async (req, res) => {
  const { nome, email, senha, dataNascimento } = req.body;

  if (!nome || !email || !senha || !dataNascimento) {
    return res.status(400).json({
      message: "Todos os campos são obrigatórios."
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(senha, 10);

    await db.run(
      "INSERT INTO usuarios (nome, email, senha, dataNascimento) VALUES (?, ?, ?, ?)",
      [nome, email, hashedPassword, dataNascimento]
    );

    res.status(201).json({
      message: "Usuário cadastrado com sucesso!"
    });

  } catch (error) {
    if (error.message.includes("UNIQUE")) {
      res.status(400).json({
        message: "E-mail já cadastrado."
      });
    } else {
      console.error(error);
      res.status(500).json({
        message: "Erro no servidor."
      });
    }
  }
});


// ================= LOGIN =================
app.post("/api/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({
      message: "Email e senha são obrigatórios."
    });
  }

  try {
    const user = await db.get(
      "SELECT * FROM usuarios WHERE email = ?",
      [email]
    );

    if (!user) {
      return res.status(400).json({
        message: "Usuário não encontrado."
      });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha);

    if (!senhaValida) {
      return res.status(400).json({
        message: "Senha incorreta."
      });
    }

    res.status(200).json({
      message: "Login realizado com sucesso",
      token: "fake-token",
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email
      }
    });

  } catch (error) {
  console.error("ERRO LOGIN:", error);
  alert("Erro ao conectar com o servidor.");
}
});


// ================= SERVER =================
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});