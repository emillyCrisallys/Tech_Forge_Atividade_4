// models/userModel.js

const users = [];
let currentId = 1;

/**
 * Adiciona um novo usuário ao array em memória.
 * @param {object} user - O objeto do usuário contendo username, email e passwordHash.
 */
const addUser = (user) => {
  if (!user.username || !user.email || !user.passwordHash) {
    throw new Error("Dados do usuário incompletos.");
  }

  const newUser = {
    id: currentId++,
    username: user.username,
    email: user.email,
    passwordHash: user.passwordHash, 
  };

  users.push(newUser);
  console.log("Usuário adicionado ao modelo:", newUser);
  return newUser;
};

/**
 * Busca um usuário pelo nome de usuário.
 * @param {string} username - O nome de usuário a ser buscado.
 * @returns {object | undefined} - O usuário encontrado ou undefined.
 */
const findByUsername = (username) => {
  console.log("Buscando usuário:", username);
  const user = users.find((u) => u.username === username);
  console.log("Resultado da busca:", user);
  return user;
};

// Exporta as funções do modelo
module.exports = {
  addUser,
  findByUsername,
};