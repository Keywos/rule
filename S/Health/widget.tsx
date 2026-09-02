import { Script, Widget } from "scripting";
import { fetchLatestAndBaselines } from "./utils/health";
import { fetchTodayActivity } from "./utils/activity";
import { analyzeStress, StressLevel } from "./utils/stress";
import { SmallWidget } from "./components/small_widget";
import { MediumWidget } from "./components/medium_widget";
import { Color } from "scripting";
import { i18n } from "./i18n";

// 背景渐变色方案（根据 HRV 压力等级）
 const levelGradient: Record<StressLevel, { top: Color; bottom: Color }> = {
  [StressLevel.Excellent]: { top: "systemGreen" as Color, bottom: "systemTeal" as Color },
  [StressLevel.Good]: { top: "systemMint" as Color, bottom: "systemCyan" as Color },
  [StressLevel.Warning]: { top: "systemOrange" as Color, bottom: "systemYellow" as Color },
  [StressLevel.Overload]: { top: "systemPink" as Color, bottom: "systemRed" as Color },
}; 

// 状态图标映射
const statusIconMap: Record<StressLevel, string> = {
  [StressLevel.Excellent]: "figure.gymnastics",
  [StressLevel.Good]: "face.smiling",
  [StressLevel.Warning]: "exclamationmark.triangle.fill",
  [StressLevel.Overload]: "exclamationmark.octagon.fill",
};

// 状态文本映射
const statusTextMap: Record<StressLevel, string> = {
  [StressLevel.Excellent]: i18n.stress.excellent,
  [StressLevel.Good]: i18n.stress.good,
  [StressLevel.Warning]: i18n.stress.warning,
  [StressLevel.Overload]: i18n.stress.overload,
};

async function main() {
  if (!Script.hasFullAccess) {
    console.error(i18n.noPermission);
  }

  const { hrv, hr, day_light, wrist_temp } = await fetchLatestAndBaselines();
  const hrvValue = hrv.latest;
  const heartRate = hr.latest;
  const hrvBaseline = hrv.baseline7d;
  const hrBaseline = hr.baseline7d;
  const hrvList = hrv.hrvlist ?? null;
  const hr24h = hr.base24h ?? null;

  const level = analyzeStress(hrvValue);

  const widgetFamily = Widget.family;

  let steps: number | null = null;

  if (widgetFamily === "systemSmall" || widgetFamily === "systemMedium") {
    const activityData = await fetchTodayActivity();
    steps = activityData.steps;
  }

  // =========================
  // 5. UI 状态
  // =========================
  const updateTime = new Date();

  const gradient = level ? levelGradient[level] : { top: "systemGray5" as Color, bottom: "systemGray4" as Color };

  const status = level ? statusTextMap[level] : i18n.stress.noData;

  const statusIcon = level ? statusIconMap[level] : "questionmark.circle";

  // =========================
  // 6. Render widgets
  // =========================
  if (widgetFamily === "systemSmall") {
    Widget.present(<SmallWidget hrvValue={hrvValue} level={level} updateTime={updateTime} gradient={gradient} status={status} statusIcon={statusIcon} hrvHistory={hrvList} steps={steps} wristTemp={wrist_temp} />);
  } else if (widgetFamily === "systemMedium") {
    Widget.present(
      <MediumWidget
        hrvValue={hrvValue}
        heartRate={heartRate}
        hrvBaseline={hrvBaseline}
        hrBaseline={hrBaseline}
        level={level}
        updateTime={updateTime}
        gradient={gradient}
        status={status}
        statusIcon={statusIcon}
        steps={steps}
        hrvHistory={hrvList}
        hrh={hr24h}
        wrist_temp={wrist_temp}
        day_light={day_light}
      />,
    );
  } else {
    Widget.present(
      <MediumWidget
        hrvValue={hrvValue}
        heartRate={heartRate}
        hrvBaseline={hrvBaseline}
        hrBaseline={hrBaseline}
        level={level}
        updateTime={updateTime}
        gradient={gradient}
        status={status}
        statusIcon={statusIcon}
        steps={steps}
        hrvHistory={hrvList}
        hrh={hr24h}
        wrist_temp={wrist_temp}
        day_light={day_light}
      />,
    );
  }
}

main();
