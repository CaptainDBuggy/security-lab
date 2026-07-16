const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');

const seedPath = path.join(__dirname, 'seed.json');
const dataPath = () => path.join(app.getPath('userData'), 'progress.json');

function loadData() {
  try {
    if (!fs.existsSync(dataPath())) {
      fs.copyFileSync(seedPath, dataPath());
    }
    return JSON.parse(fs.readFileSync(dataPath(), 'utf8'));
  } catch (e) {
    // Fall back to the bundled seed if the user copy is missing/corrupt.
    return JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  }
}

function saveData(data) {
  fs.writeFileSync(dataPath(), JSON.stringify(data, null, 2));
  return true;
}

ipcMain.handle('load', () => loadData());
ipcMain.handle('save', (_e, data) => saveData(data));
ipcMain.handle('reset', () => {
  fs.copyFileSync(seedPath, dataPath());
  return loadData();
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1160,
    height: 860,
    backgroundColor: '#0b0f14',
    title: 'CTF Progress Tracker',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile('index.html');
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
