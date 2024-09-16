const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = 'minhaChaveSecreta';


const users = [];


app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = { id: users.length + 1, username, password: hashedPassword };
    users.push(user);
    res.status(201).send('Usuário registrado com sucesso');
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ auth: true, token });
    } else {
        res.status(401).send('Credenciais inválidas');
    }
});


const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};


app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Você acessou um lugar especial!', user: req.user });
});

app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000');
});
