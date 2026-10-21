#if canImport(SwiftUI) && canImport(AuthenticationServices)
import SwiftUI

/// The branded "Sign in with Identvia" button, matching the web button (light, dark and brand themes).
@available(iOS 15, macOS 12, *)
public struct SignInWithIdentviaButton: View {
    public enum Label: String { case signIn = "Sign in with Identvia", continueWith = "Continue with Identvia", signUp = "Sign up with Identvia" }
    public enum Theme { case light, dark, brand }

    let label: Label
    let theme: Theme
    let isLoading: Bool
    let action: () -> Void

    public init(_ label: Label = .signIn, theme: Theme = .light, isLoading: Bool = false, action: @escaping () -> Void) {
        self.label = label; self.theme = theme; self.isLoading = isLoading; self.action = action
    }

    private static let brand = Color(red: 0x4B / 255, green: 0x4A / 255, blue: 0xCF / 255)

    private var colors: (bg: Color, border: Color, fg: Color) {
        switch theme {
        case .light: return (.white, Color(red: 0xD4 / 255, green: 0xD4 / 255, blue: 0xD8 / 255), Color(red: 0x18 / 255, green: 0x18 / 255, blue: 0x1B / 255))
        case .dark: return (Color(red: 0x18 / 255, green: 0x18 / 255, blue: 0x1B / 255), Color(red: 0x3F / 255, green: 0x3F / 255, blue: 0x46 / 255), .white)
        case .brand: return (Self.brand, Self.brand, .white)
        }
    }

    public var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if isLoading { ProgressView().tint(colors.fg) } else { IdentviaMark().frame(width: 20, height: 20) }
                Text(label.rawValue).font(.system(size: 15, weight: .semibold)).lineLimit(1)
            }
            .foregroundColor(colors.fg)
            .padding(.horizontal, 16)
            .frame(minHeight: 44)
            .background(RoundedRectangle(cornerRadius: 8).fill(colors.bg))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(colors.border, lineWidth: 1))
        }
        .buttonStyle(.plain)
        .disabled(isLoading)
        .accessibilityLabel(Text(label.rawValue))
    }
}

/// The Identvia mark: a brand square with a dot and a check.
@available(iOS 15, macOS 12, *)
public struct IdentviaMark: View {
    public init() {}
    public var body: some View {
        GeometryReader { g in
            let s = g.size.width / 28
            ZStack {
                RoundedRectangle(cornerRadius: 8 * s).fill(Color(red: 0x4B / 255, green: 0x4A / 255, blue: 0xCF / 255))
                Circle().fill(.white).frame(width: 4.2 * s, height: 4.2 * s).position(x: 9.25 * s, y: 8.25 * s)
                Path { p in
                    p.move(to: CGPoint(x: 8.6 * s, y: 13.4 * s))
                    p.addLine(to: CGPoint(x: 12.5 * s, y: 19.5 * s))
                    p.addLine(to: CGPoint(x: 20.4 * s, y: 8 * s))
                }.stroke(.white, style: StrokeStyle(lineWidth: 2.6 * s, lineCap: .round, lineJoin: .round))
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .accessibilityHidden(true)
    }
}
#endif
