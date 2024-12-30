using QRCoder;
using System.Drawing;
using System.Drawing.Imaging;

public class QrCodeController : Controller
{
    [HttpGet]
    public IActionResult GenerateQrCode(string qrCodeUri)
    {
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new QRCode(qrCodeData);
        using var bitmap = qrCode.GetGraphic(20);
        using var stream = new MemoryStream();
        
        bitmap.Save(stream, ImageFormat.Png);
        return File(stream.ToArray(), "image/png");
    }
} 