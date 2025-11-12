// server.js

// --- NOVAS IMPORTAÇÕES JWT & DOTENV (AULA 5) ---
require("dotenv").config(); // 1. Carrega as variáveis de ambiente do .env
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET; // 1. Chave secreta do JWT
// ------------------------------------

const express = require("express");
const app = express();
const port = 3000;
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const cors = require("cors");

// --- IMPORTAÇÕES EXISTENTES (AULA 4) ---
const bcrypt = require("bcryptjs");
// 
const userModel = require("./models/userModel"); 

// --- MIDDLEWARES GLOBAIS ---
app.use(cors());
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 

// --- LÓGICA DE UPLOAD (AULA 3) ---

const createUploadDirectory = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`Diretório ${dir} criado automaticamente.`);
  }
};

const fileFilter = (req, file, cb) => {
  if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
    cb(null, true);
  } else {
    cb(
      new Error("Tipo de arquivo inválido. Apenas JPG e PNG são permitidos."),
      false
    );
  }
};

const MAX_FILE_SIZE = 5 * 1024 * 1024;

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDiretorio = "uploads/";
    createUploadDirectory(uploadDiretorio);
    cb(null, uploadDiretorio);
  },
  filename: function (req, file, cb) {
    // Garante que o nome seja único
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 10,
  },
});

// --- MIDDLEWARE DE PROTEÇÃO DE ROTAS 
function verificarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  
  
  const token = authHeader && authHeader.split(" ")[1];
  
  if (!token) {
    
    return res.status(401).json({ message: "Acesso negado. Token não fornecido." }); 
  }

  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      
      return res.status(403).json({ message: "Token inválido ou expirado." });
    }

    
    req.userId = decoded.userId;
    next(); 
  });
}

// ====================================================================
// --- ROTAS DE AUTENTICAÇÃO (API - POST) ---
// ====================================================================

// Rota de Cadastro (/register - Base Aula 4)
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    }

    const existingUser = userModel.findByUsername(username);
    if (existingUser) {
      return res.status(400).json({ message: "Este nome de usuário já está em uso." });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = userModel.addUser({
      username,
      email,
      passwordHash,
    });

    res.status(201).json({
      message: "Usuário cadastrado com sucesso! Prossiga para o login.",
      user: {
        id: newUser.id,
        username: newUser.username,
      },
    });
  } catch (error) {
    console.error("Erro no /register:", error);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});

// Rota de Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username e password são obrigatórios." });
    }

    // 1. Buscar o usuário
    const user = userModel.findByUsername(username);

    // 2. Verificar usuário e senha
    if (!user) {
      // Mensagem genérica para segurança
      return res.status(401).json({ message: "Credenciais inválidas." });
    }
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      // Mensagem genérica para segurança
      return res.status(401).json({ message: "Credenciais inválidas." });
    }

    // 3. Gera o Token JWT
    const payload = { userId: user.id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" }); // Expira em 1 hora

    // 4. Retorna o token
    res.status(200).json({
      message: "Login bem-sucedido. Token gerado.",
      token: token,
    });
  } catch (error) {
    console.error("Erro no /login:", error);
    res.status(500).json({ message: "Erro interno no servidor." });
  }
});


// Rota de Upload 
// O middleware verificarToken é aplicado AQUI, protegendo esta rota.
app.post("/upload", verificarToken, (req, res) => {
  
  console.log(`[UPLOAD] Usuário autenticado com ID: ${req.userId} está fazendo upload.`);

  upload.array("meusArquivos", 10)(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_COUNT") {
        return res.status(400).json({ message: "Limite de 10 arquivos excedido." });
      }
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          message: `Arquivo muito grande. O limite é ${
            MAX_FILE_SIZE / 1024 / 1024
          }MB.`,
        });
      }
      return res
        .status(400)
        .json({ message: `Erro do Multer: ${err.message}` });
    } else if (err) {
      return res.status(400).json({ message: err.message });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: "Nenhum arquivo enviado." });
    }

    res.status(200).json({
      message: `${req.files.length} arquivos enviados com sucesso!`,
      fileCount: req.files.length,
      uploadedBy: req.userId 
    });
  });
});

// ====================================================================
// --- ROTAS DE FRONTEND (SERVIR HTML - GET) ---
// ====================================================================

// Rota página principal de Upload
app.get("/", (req, res) => {
  const htmlFilePath = path.join(__dirname, "frontend_atividade_completo.html");

  if (fs.existsSync(htmlFilePath)) {
    res.sendFile(htmlFilePath);
  } else {
    res.status(404).send("Erro: Arquivo frontend_atividade_completo.html não encontrado.");
  }
});

// Rota frontend de Cadastro (/register-page)
app.get("/register-page", (req, res) => {
  const htmlFilePath = path.join(__dirname, "register.html");

  if (fs.existsSync(htmlFilePath)) {
    res.sendFile(htmlFilePath);
  } else {
    res.status(404).send("Erro: Arquivo register.html não encontrado.");
  }
});

// Rota frontend de Login (/login) 
app.get("/login", (req, res) => {
  const htmlFilePath = path.join(__dirname, "login.html");

  if (fs.existsSync(htmlFilePath)) {
    res.sendFile(htmlFilePath);
  } else {
    res.status(404).send("Erro: Arquivo login.html não encontrado. Por favor, crie-o.");
  }
});


app.listen(port, () => {
  console.log(`Servidor rodando em: http://localhost:${port}`);
  console.log(`Página de Cadastro: http://localhost:${port}/register-page`);
  console.log(`Página de Login: http://localhost:${port}/login`);
  console.log(`Página de Upload: http://localhost:${port}/`);
});