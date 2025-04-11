import fs from 'fs';
import { createCanvas } from 'canvas';

const sizes = [16, 48, 128];
const iconColor = '#4CAF50'; // Green color matching our UI

function generateIcon(size) {
    const canvas = createCanvas(size, size);
    const ctx = canvas.getContext('2d');

    // Fill background
    ctx.fillStyle = iconColor;
    ctx.fillRect(0, 0, size, size);

    // Draw shield shape
    ctx.beginPath();
    ctx.moveTo(size/2, size*0.1);
    ctx.lineTo(size*0.8, size*0.3);
    ctx.lineTo(size*0.8, size*0.6);
    ctx.lineTo(size/2, size*0.9);
    ctx.lineTo(size*0.2, size*0.6);
    ctx.lineTo(size*0.2, size*0.3);
    ctx.closePath();
    
    // Fill shield
    ctx.fillStyle = 'white';
    ctx.fill();

    // Draw checkmark
    ctx.beginPath();
    ctx.strokeStyle = iconColor;
    ctx.lineWidth = size * 0.1;
    ctx.moveTo(size*0.3, size*0.5);
    ctx.lineTo(size*0.45, size*0.65);
    ctx.lineTo(size*0.7, size*0.35);
    ctx.stroke();

    return canvas.toBuffer();
}

// Create icons directory if it doesn't exist
if (!fs.existsSync('icons')) {
    fs.mkdirSync('icons');
}

// Generate icons for each size
sizes.forEach(size => {
    const iconBuffer = generateIcon(size);
    fs.writeFileSync(`icons/icon${size}.png`, iconBuffer);
    console.log(`Generated icon${size}.png`);
}); 