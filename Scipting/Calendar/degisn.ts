import type { ShapeStyle, DynamicShapeStyle, ColorStringRGBA } from 'scripting'

type ColorRGBA = ColorStringRGBA | { light: ColorStringRGBA, dark: ColorStringRGBA }

export const colors = {
    systemRed: {
        light: 'rgba(255,56,60,1)',
        dark: 'rgba(255,66,69,1)',
    },
    systemGreen: {
        light: 'rgba(52,199,89,1)',
        dark: 'rgba(48,209,88,1)',
    }
} satisfies Record<string, ColorRGBA>

export function color(rgba: ColorRGBA, alpha: number) {
    if (typeof rgba === 'string') {
        return rgba.replace(/,\s*[\d.]+\)$/, `,${alpha})`) as ColorStringRGBA
    }
    return {
        light: rgba.light.replace(/,\s*[\d.]+\)$/, `,${alpha})`),
        dark: rgba.dark.replace(/,\s*[\d.]+\)$/, `,${alpha})`)
    } as ColorRGBA
}