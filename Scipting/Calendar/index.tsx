import {
  Button,
  Divider,
  HStack,
  Image,
  List,
  Navigation,
  NavigationLink,
  NavigationStack,
  Picker,
  Script,
  Section,
  Spacer,
  Text,
  TextField,
  useEffect,
  useState,
  VStack,
  Widget,
} from 'scripting'

// Helper to get ISO week number
function getCurrentWeek() {
  const date = new Date()
  date.setHours(0, 0, 0, 0)
  // Thursday in current week decides the year.
  date.setDate(date.getDate() + 3 - ((date.getDay() + 6) % 7))
  // January 4 is always in week 1.
  const week1 = new Date(date.getFullYear(), 0, 4)
  // Adjust to Thursday in week 1 and count number of weeks from date to week1.
  return (
    1 +
    Math.round(
      ((date.getTime() - week1.getTime()) / 86400000 -
        3 +
        ((week1.getDay() + 6) % 7)) /
        7,
    )
  )
}

function formatDate(date: Date) {
  const y = date.getFullYear()
  const m = (date.getMonth() + 1).toString().padStart(2, '0')
  const d = date.getDate().toString().padStart(2, '0')
  return `${y}/${m}/${d}`
}

function WeekCalculator() {
  const [year, setYear] = useState(new Date().getFullYear().toString())
  const [week, setWeek] = useState(getCurrentWeek().toString())
  const [result, setResult] = useState<{
    start: string
    end: string
    diff: number
  } | null>(null)

  useEffect(() => {
    calculate()
  }, [year, week])

  const resetToCurrent = () => {
    setYear(new Date().getFullYear().toString())
    setWeek(getCurrentWeek().toString())
  }

  const calculate = () => {
    const y = parseInt(year)
    const w = parseInt(week)

    if (isNaN(y) || isNaN(w)) {
      setResult(null)
      return
    }

    // ISO 8601 Algorithm
    const jan4 = new Date(y, 0, 4)
    const dayOfWeek = jan4.getDay() || 7
    const startOfFirstWeek = new Date(jan4)
    startOfFirstWeek.setDate(jan4.getDate() - dayOfWeek + 1)

    const startOfWeek = new Date(startOfFirstWeek)
    startOfWeek.setDate(startOfFirstWeek.getDate() + (w - 1) * 7)

    const endOfWeek = new Date(startOfWeek)
    endOfWeek.setDate(startOfWeek.getDate() + 6)

    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const target = new Date(startOfWeek)
    target.setHours(0, 0, 0, 0)

    const diffTime = target.getTime() - today.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))

    setResult({
      start: formatDate(startOfWeek),
      end: formatDate(endOfWeek),
      diff: diffDays,
    })
  }

  return (
    <NavigationStack>
      <List
        navigationTitle='Week Calculator'
        toolbar={{
          topBarTrailing: <Button title='This Week' action={resetToCurrent} />,
        }}
      >
        <Section header={<Text>INPUT</Text>}>
          <HStack>
            <Image
              systemName='calendar'
              foregroundStyle='blue'
              imageScale='large'
            />
            <TextField
              title='Year'
              value={year}
              onChanged={setYear}
              keyboardType='numberPad'
            />
            <Divider />
            <Image
              systemName='number.square'
              foregroundStyle='blue'
              imageScale='large'
            />
            <TextField
              title='Week'
              value={week}
              onChanged={setWeek}
              keyboardType='numberPad'
              prompt='e.g. 1'
            />
          </HStack>
        </Section>

        {result && (
          <Section header={<Text>RESULT</Text>}>
            <HStack>
              <VStack alignment='leading'>
                <Text font='caption' foregroundStyle='secondaryLabel'>
                  Start Date
                </Text>
                <Text font='title3'>{result.start}</Text>
              </VStack>
              <Spacer />
              <Image systemName='arrow.right' foregroundStyle='tertiaryLabel' />
            </HStack>
            <HStack>
              <VStack alignment='leading'>
                <Text font='caption' foregroundStyle='secondaryLabel'>
                  End Date
                </Text>
                <Text font='title3'>{result.end}</Text>
              </VStack>
              <Spacer />
              <Image systemName='arrow.left' foregroundStyle='tertiaryLabel' />
            </HStack>
            <HStack>
              <Image
                systemName='clock'
                foregroundStyle={result.diff >= 0 ? 'green' : 'orange'}
              />
              <Text>Days from Today</Text>
              <Spacer />
              <Text
                font='headline'
                foregroundStyle={result.diff >= 0 ? 'green' : 'orange'}
              >
                {result.diff} {Math.abs(result.diff) === 1 ? 'day' : 'days'}
              </Text>
            </HStack>
          </Section>
        )}
      </List>
    </NavigationStack>
  )
}
function App() {
  const [firstDayOfWeek, setFirstDayOfWeek] = useState(Storage.get<string>('firstDayOfWeek') || '0')

  return (
    <NavigationStack>
      <List navigationTitle='Calendar'>
        <Section>
          <NavigationLink title='Week Calculator' destination={<WeekCalculator />} />
        </Section>
        <Section header={<Text>Settings</Text>}>
          <Picker
            value={firstDayOfWeek}
            onChanged={(val: string) => {
              setFirstDayOfWeek(val)
              Storage.set('firstDayOfWeek', val)
              Widget.reloadAll()
            }}
            pickerStyle="menu"
            label={<Text>Start Week on</Text>}
          >
            <Text tag='0'>Sunday</Text>
            <Text tag='1'>Monday</Text>
          </Picker>
        </Section>
        <Section>
          <Button title='Preview Widget' action={() => Widget.preview()}></Button>
        </Section>
      </List>
    </NavigationStack>
  )
}

async function main() {
  await Navigation.present({ element: <App /> })
  Script.exit()
}

main()
