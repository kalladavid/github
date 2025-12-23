const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const { sequelize, Product } = require('./models');
const { router: authRouter, authenticate, requireAdmin } = require('./auth');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Mount auth routes
app.use('/api/auth', authRouter);

// Simple health
app.get('/', (req, res) => res.json({ message: "NoelPhones API up" }));

// Products (public)
app.get('/api/products', async (req, res) => {
  const products = await Product.findAll();
  res.json(products);
});

app.get('/api/products/:id', async (req, res) => {
  const p = await Product.findByPk(req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  res.json(p);
});

// Admin create product (protected)
app.post('/api/products', authenticate, requireAdmin, async (req, res) => {
  try {
    const { sku, brand, model, description, price_cents, stock } = req.body;
    const product = await Product.create({ sku, brand, model, description, price_cents, stock });
    res.status(201).json(product);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 4000;
async function start() {
  await sequelize.authenticate();
  await sequelize.sync(); // In production use migrations
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
start();