<?php
// You can add fake logic here if needed, like "IP logging" or "System Scan"
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>System Breach</title>
  <style>
    body {
      background: black;
      color: #00ff00;
      font-family: 'Courier New', Courier, monospace;
      overflow: hidden;
      text-align: center;
    }

    h1 {
      font-size: 3rem;
      margin-top: 20vh;
      animation: blink 1s infinite;
    }

    p {
      font-size: 1.5rem;
    }

    #matrix {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      pointer-events: none;
      z-index: -1;
    }

    @keyframes blink {
      0% { opacity: 1; }
      50% { opacity: 0.1; }
      100% { opacity: 1; }
    }
  </style>
</head>
<body>
  <canvas id="matrix"></canvas>
  <h1>⚠ YOU WHERE BEEN PWN3D ⚠</h1>
  <p>All your data has been encrypted.<br>Contact d3hvck@vuln.az to restore access.</p>

  <script>
    const canvas = document.getElementById("matrix");
    const ctx = canvas.getContext("2d");

    canvas.height = window.innerHeight;
    canvas.width = window.innerWidth;

    const letters = "01";
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array.from({ length: columns }).fill(1);

    function draw() {
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#0F0";
      ctx.font = fontSize + "px monospace";

      for (let i = 0; i < drops.length; i++) {
        const text = letters[Math.floor(Math.random() * letters.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }

        drops[i]++;
      }
    }

    setInterval(draw, 33);
  </script>
</body>
</html>