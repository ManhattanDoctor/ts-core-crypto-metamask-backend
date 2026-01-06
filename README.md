# @ts-core/crypto-metamask-backend

Серверная библиотека для работы с криптографическими подписями Ethereum/Metamask. Предоставляет инструменты для подписи сообщений приватным ключом и верификации подписей, созданных через Metamask.

## Установка

```bash
npm install @ts-core/crypto-metamask-backend
```

## Зависимости

- `@ts-core/common` — базовые классы и интерфейсы
- `@metamask/eth-sig-util` — утилиты для работы с подписями Ethereum

## Основные классы

### Metamask

Класс для подписи и верификации сообщений с использованием алгоритма Keccak (используется в Ethereum).

```typescript
import { Metamask } from '@ts-core/crypto-metamask-backend';

// Подпись сообщения приватным ключом
const privateKey = 'your-private-key-hex';
const message = 'Hello, Ethereum!';
const signature = Metamask.sign(message, privateKey);

// Верификация подписи по адресу кошелька
const address = '0x1234567890abcdef...';
const isValid = Metamask.verify(message, signature, address);
console.log(isValid);  // true если подпись валидна
```

### TransportCryptoManagerMetamaskBackend

Менеджер криптографии для подписи и верификации транспортных команд в распределённых системах:

```typescript
import { TransportCryptoManagerMetamaskBackend } from '@ts-core/crypto-metamask-backend';

const cryptoManager = new TransportCryptoManagerMetamaskBackend();

// Подпись транспортной команды
const signature = await cryptoManager.sign(command, nonce, privateKey);

// Верификация транспортной команды
const isValid = await cryptoManager.verify(command, {
    value: signature,
    nonce: nonce,
    publicKey: walletAddress  // Ethereum адрес
});
```

## API Reference

### Metamask

| Метод | Описание |
|-------|----------|
| `sign(message, privateKey): string` | Подпись сообщения приватным ключом |
| `verify(message, signature, address): boolean` | Проверка подписи по адресу кошелька |

### Параметры

| Параметр | Тип | Описание |
|----------|-----|----------|
| `message` | `string` | Сообщение для подписи/верификации |
| `privateKey` | `string` | Приватный ключ в формате hex (без префикса 0x) |
| `signature` | `string` | Подпись в формате hex |
| `address` | `string` | Ethereum адрес (с префиксом 0x) |

### TransportCryptoManagerMetamaskBackend

| Метод | Описание |
|-------|----------|
| `sign<U>(command, nonce, privateKey): Promise<string>` | Подпись транспортной команды |
| `verify<U>(command, signature): Promise<boolean>` | Верификация транспортной команды |
| `algorithm: string` | Возвращает `'KeccakMetamask'` |

## Пример использования с dApp

### Серверная сторона (Node.js/NestJS)

```typescript
import { Metamask } from '@ts-core/crypto-metamask-backend';

// Верификация подписи, полученной от клиента
async function verifyUserSignature(
    message: string,
    signature: string,
    expectedAddress: string
): Promise<boolean> {
    return Metamask.verify(message, signature, expectedAddress);
}

// Пример в контроллере
@Post('verify')
async verify(@Body() dto: VerifyDto) {
    const isValid = Metamask.verify(
        dto.message,
        dto.signature,
        dto.address
    );

    if (!isValid) {
        throw new UnauthorizedException('Invalid signature');
    }

    return { success: true };
}
```

### Использование с Transport

```typescript
import { TransportCryptoManagerMetamaskBackend } from '@ts-core/crypto-metamask-backend';

class MyTransport extends Transport {
    constructor() {
        super();
        this.cryptoManager = new TransportCryptoManagerMetamaskBackend();
    }
}
```

## Особенности

- Использует алгоритм `personalSign` из спецификации EIP-191
- Подписи совместимы с Metamask и другими Ethereum-кошельками
- Верификация выполняется по Ethereum-адресу (не по публичному ключу)
- Сравнение адресов регистронезависимое

## Связанные пакеты

- `@ts-core/crypto-metamask-frontend` — клиентская библиотека для подписи через Metamask в браузере

## Автор

**Renat Gubaev** — [renat.gubaev@gmail.com](mailto:renat.gubaev@gmail.com)

- GitHub: [ManhattanDoctor](https://github.com/ManhattanDoctor)
- Repository: [ts-core-crypto-metamask-backend](https://github.com/ManhattanDoctor/ts-core-crypto-metamask-backend)

## Лицензия

ISC
