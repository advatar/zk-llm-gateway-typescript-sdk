/** Base error for the SDK. */
export class ZkLlmGatewayError extends Error {
  readonly name: string = 'ZkLlmGatewayError';
}

export class InvalidTokenClass extends ZkLlmGatewayError {
  readonly name: string = 'InvalidTokenClass';
}

export class InvalidGatewayPublicKey extends ZkLlmGatewayError {
  readonly name: string = 'InvalidGatewayPublicKey';
}

export class CryptoError extends ZkLlmGatewayError {
  readonly name: string = 'CryptoError';
}

export class ProtocolError extends ZkLlmGatewayError {
  readonly name: string = 'ProtocolError';
}

export class HttpError extends ZkLlmGatewayError {
  readonly name: string = 'HttpError';
  constructor(public readonly statusCode: number, message: string) {
    super(message);
  }
}

export class GatewayError extends ZkLlmGatewayError {
  readonly name: string = 'GatewayError';
  constructor(public readonly code: string, message: string) {
    super(message);
  }
}

export class InvalidPadding extends ZkLlmGatewayError {
  readonly name: string = 'InvalidPadding';
}

export class PayloadTooLarge extends ZkLlmGatewayError {
  readonly name: string = 'PayloadTooLarge';
  constructor(public readonly actual: number, public readonly limit: number) {
    super(`payload too large: ${actual} > ${limit}`);
  }
}

export class TicketExhausted extends ZkLlmGatewayError {
  readonly name: string = 'TicketExhausted';
}
