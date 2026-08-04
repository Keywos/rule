import {
  Button,
  Image,
  List,
  Navigation,
  ProgressView,
  Script,
  Section,
  Text,
  useEffect,
  useObservable,
} from "scripting";

export function View({ link }: { link: string }) {
  const dismiss = Navigation.useDismiss();
  return (
    <StackView
      link={link}
      navigationTitle={Script.name}
      toolbar={{
        topBarLeading: [<Button title={"退出"} systemImage={"xmark"} action={dismiss} />],
        topBarTrailing: [
          <Button title={"最小化"} systemImage={"chevron.down"} action={() => Script.minimize()} />,
        ],
        // topBarLeading: [
        //   <Button title={"最小化"} systemImage={"xmark"} action={() => Script.minimize()} />,
        // ],
      }}
    />
  );
}

function StackView({ link }: { link: string }) {
  return (
    <List>
      <Section title={"链接"}>
        <Text
          lineLimit={1}
          contextMenu={{
            menuItems: (
              <>
                <Section>
                  <Button
                    title={"拷贝"}
                    systemImage={"doc.on.doc"}
                    action={() => Pasteboard.setString(link)}
                  />
                </Section>
                <Section>
                  <Button
                    title={"共享"}
                    systemImage={"square.and.arrow.up"}
                    action={() => ShareSheet.present([link])}
                  />
                </Section>
              </>
            ),
          }}>
          {link}
        </Text>
      </Section>

      <Section title={"二维码"}>
        <QRCodeView link={link} listRowInsets={0} background={"white"} />
      </Section>
    </List>
  );
}

function QRCodeView({ link }: { link: string }) {
  const image = useObservable<UIImage | null>();
  async function init() {
    image.setValue(await QRCode.generate(link));
  }
  useEffect(() => {
    init();
  }, []);
  if (image.value === undefined) return <ProgressView />;
  else if (image.value === null) return <Text>{"生成二维码失败"}</Text>;
  else return <Image image={image.value} resizable={true} scaleToFit={true} padding={true} />;
}
