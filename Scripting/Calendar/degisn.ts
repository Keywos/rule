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
    },
    systemBlue: {
        light: 'rgba(0,122,255,1)',
        dark: 'rgba(10,132,255,1)',
    }
} satisfies Record<string, ColorRGBA>

export const todayText: DynamicShapeStyle = {
    light: 'rgba(255,255,255,0.99)',
    dark: 'rgba(255,255,255,0.9)'
}

export const labText: DynamicShapeStyle = {
    light: 'rgba(177,177,177,0.85)',
    dark: 'rgba(177,177,177,0.8)'
}


export function color(rgba: ColorRGBA, alpha: number) {
    if (typeof rgba === 'string') {
        return rgba.replace(/,\s*[\d.]+\)$/, `,${alpha})`) as ColorStringRGBA
    }
    return {
        light: rgba.light.replace(/,\s*[\d.]+\)$/, `,${alpha})`),
        dark: rgba.dark.replace(/,\s*[\d.]+\)$/, `,${alpha})`)
    } as ColorRGBA
}