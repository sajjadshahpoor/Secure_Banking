document.addEventListener("DOMContentLoaded", () => {
  const qrElement = document.querySelector("[data-qr-text]");
  if (!qrElement || typeof QRCode === "undefined") {
    return;
  }

  const qrText = qrElement.dataset.qrText;
  if (!qrText) {
    return;
  }

  new QRCode(qrElement, {
    text: qrText,
    width: 220,
    height: 220,
  });
});
