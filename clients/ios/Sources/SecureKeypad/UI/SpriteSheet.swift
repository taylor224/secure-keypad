#if canImport(UIKit) && !os(watchOS)
import CoreGraphics
import UIKit

/// A decoded 8-bit coverage sprite sheet plus a tinted RGBA `CGImage` of it. Cell `t` is at column
/// `t % cols`, row `t / cols`. The tinted image is regenerated when the text color changes (dark mode).
final class SpriteSheet {
    let info: SpriteInfo
    let width: Int
    let height: Int
    private let coverage: [UInt8]
    private var tintedColor: UIColor?
    private(set) var tinted: CGImage?

    init?(png: Data, info: SpriteInfo) {
        guard !png.isEmpty, let ui = UIImage(data: png), let cg = ui.cgImage else { return nil }
        let w = cg.width, h = cg.height
        guard w > 0, h > 0, w <= 16384, h <= 16384 else { return nil }
        var buf = [UInt8](repeating: 0, count: w * h)
        let ok: Bool = buf.withUnsafeMutableBytes { raw in
            guard let ctx = CGContext(data: raw.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w,
                                      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)
            else { return false }
            ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }
        guard ok else { return nil }
        self.info = info
        self.width = w
        self.height = h
        self.coverage = buf
    }

    /// Unit-space rect of cell `t`, for `CALayer.contentsRect`.
    func contentsRect(cell t: Int) -> CGRect {
        let col = t % info.cols, row = t / info.cols
        return CGRect(x: CGFloat(col * info.w) / CGFloat(width), y: CGFloat(row * info.h) / CGFloat(height),
                      width: CGFloat(info.w) / CGFloat(width), height: CGFloat(info.h) / CGFloat(height))
    }

    /// Premultiplied RGBA image where alpha = coverage and color = `color`.
    func tintedImage(_ color: UIColor) -> CGImage? {
        if let img = tinted, tintedColor == color { return img }
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 1
        color.getRed(&r, green: &g, blue: &b, alpha: &a)
        let cr = UInt32(max(0, min(255, r * 255))), cgc = UInt32(max(0, min(255, g * 255))), cb = UInt32(max(0, min(255, b * 255)))
        var rgba = [UInt8](repeating: 0, count: width * height * 4)
        for i in 0..<(width * height) {
            let c = UInt32(coverage[i])
            if c == 0 { continue }
            rgba[i * 4] = UInt8((cr * c + 127) / 255)
            rgba[i * 4 + 1] = UInt8((cgc * c + 127) / 255)
            rgba[i * 4 + 2] = UInt8((cb * c + 127) / 255)
            rgba[i * 4 + 3] = UInt8(c)
        }
        let img: CGImage? = rgba.withUnsafeMutableBytes { raw in
            guard let ctx = CGContext(data: raw.baseAddress, width: width, height: height, bitsPerComponent: 8,
                                      bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue | CGBitmapInfo.byteOrder32Big.rawValue)
            else { return nil }
            return ctx.makeImage()
        }
        tinted = img
        tintedColor = color
        return img
    }
}
#endif
