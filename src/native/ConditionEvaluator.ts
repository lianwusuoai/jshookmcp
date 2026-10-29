/**
 * Shared condition expression validator and evaluator for breakpoints.
 *
 * The debugger domain uses `@babel/parser` parseExpression for pre-validation
 * of CDP breakpoint conditions (which V8 evaluates serverside). For Win32
 * software/hardware breakpoints we need local evaluation — this module provides
 * both validation (shared with debugger domain pattern) and evaluation.
 *
 * @module ConditionEvaluator
 */

import { parseExpression } from '@babel/parser';
import type { Expression, PrivateName } from '@babel/types';

const MAX_CONDITION_LENGTH = 50_000;
const MAX_CONDITION_NODES = 512;
const MAX_CONDITION_DEPTH = 64;
const MAX_BIGINT_LITERAL_DIGITS = 256;
const MAX_BIGINT_RESULT_BITS = 4096;
const MAX_BIGINT_EXPONENT = 4096n;

/** Register name aliases — both x86-32 and x64 names are accepted. */
const REGISTER_ALIASES: Record<string, string> = {
  // x64 → x64
  rax: 'rax',
  rbx: 'rbx',
  rcx: 'rcx',
  rdx: 'rdx',
  rsi: 'rsi',
  rdi: 'rdi',
  rsp: 'rsp',
  rbp: 'rbp',
  r8: 'r8',
  r9: 'r9',
  r10: 'r10',
  r11: 'r11',
  r12: 'r12',
  r13: 'r13',
  r14: 'r14',
  r15: 'r15',
  rip: 'rip',
  eip: 'rip',
  rflags: 'rflags',
  eflags: 'rflags',
  // x86-32 → x64 (low 32 bits mapped to full register)
  eax: 'rax',
  ebx: 'rbx',
  ecx: 'rcx',
  edx: 'rdx',
  esi: 'rsi',
  edi: 'rdi',
  esp: 'rsp',
  ebp: 'rbp',
};

export interface ConditionContext {
  /** Register values as hexadecimal strings, converted to BigInt by the safe evaluator. */
  registers: Record<string, string>;
}

type ConditionValue = bigint | number | boolean;
type NumericValue = bigint | number;
interface ConditionNodeBudget {
  nodes: number;
}

const ALLOWED_UNARY_OPERATORS = new Set(['!', '+', '-', '~']);
const ALLOWED_BINARY_OPERATORS = new Set([
  '+',
  '-',
  '*',
  '/',
  '%',
  '**',
  '&',
  '|',
  '^',
  '<<',
  '>>',
  '>>>',
  '<',
  '<=',
  '>',
  '>=',
  '==',
  '!=',
  '===',
  '!==',
]);
const ALLOWED_LOGICAL_OPERATORS = new Set(['&&', '||']);

function hasRegisterAlias(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(REGISTER_ALIASES, name);
}

function isPrivateName(node: Expression | PrivateName): node is PrivateName {
  return node.type === 'PrivateName';
}

function validateConditionNode(node: Expression, depth: number, budget: ConditionNodeBudget): void {
  if (depth > MAX_CONDITION_DEPTH) {
    throw new Error('condition expression is nested too deeply');
  }

  budget.nodes += 1;
  if (budget.nodes > MAX_CONDITION_NODES) {
    throw new Error('condition expression contains too many operations');
  }

  switch (node.type) {
    case 'NumericLiteral':
      if (!Number.isFinite(node.value)) {
        throw new Error('non-finite numeric literals are not supported');
      }
      return;
    case 'BigIntLiteral':
      if (node.value.toString().length > MAX_BIGINT_LITERAL_DIGITS) {
        throw new Error('BigInt literal is too large');
      }
      return;
    case 'BooleanLiteral':
      return;
    case 'Identifier':
      if (!hasRegisterAlias(node.name)) {
        throw new Error('unknown register name: ' + node.name);
      }
      return;
    case 'UnaryExpression':
      if (!ALLOWED_UNARY_OPERATORS.has(node.operator)) {
        throw new Error('unsupported unary operator: ' + node.operator);
      }
      if (isPrivateName(node.argument)) {
        throw new Error('private names are not supported');
      }
      validateConditionNode(node.argument, depth + 1, budget);
      return;
    case 'BinaryExpression':
      if (!ALLOWED_BINARY_OPERATORS.has(node.operator)) {
        throw new Error('unsupported binary operator: ' + node.operator);
      }
      if (isPrivateName(node.left) || isPrivateName(node.right)) {
        throw new Error('private names are not supported');
      }
      validateConditionNode(node.left, depth + 1, budget);
      validateConditionNode(node.right, depth + 1, budget);
      return;
    case 'LogicalExpression':
      if (!ALLOWED_LOGICAL_OPERATORS.has(node.operator)) {
        throw new Error('unsupported logical operator: ' + node.operator);
      }
      validateConditionNode(node.left, depth + 1, budget);
      validateConditionNode(node.right, depth + 1, budget);
      return;
    default:
      throw new Error('unsupported condition expression: ' + node.type);
  }
}

function parseConditionExpression(condition: string): Expression {
  if (condition.length > MAX_CONDITION_LENGTH) {
    throw new Error('condition is too long (max ' + MAX_CONDITION_LENGTH + ' chars)');
  }

  const expression = parseExpression(condition, {
    sourceType: 'unambiguous',
    errorRecovery: false,
  });
  validateConditionNode(expression, 0, { nodes: 0 });
  return expression;
}

function toNumeric(value: ConditionValue): NumericValue {
  return typeof value === 'boolean' ? Number(value) : value;
}

function bigintBitLength(value: bigint): number {
  const magnitude = value < 0n ? -value : value;
  return magnitude === 0n ? 0 : magnitude.toString(2).length;
}

function limitBigIntResult(value: bigint): bigint {
  if (bigintBitLength(value) > MAX_BIGINT_RESULT_BITS) {
    throw new Error('BigInt operation result is too large');
  }
  return value;
}

function evaluateBigIntBinary(operator: string, left: bigint, right: bigint): bigint {
  switch (operator) {
    case '+':
      return limitBigIntResult(left + right);
    case '-':
      return limitBigIntResult(left - right);
    case '*':
      return limitBigIntResult(left * right);
    case '/':
      return limitBigIntResult(left / right);
    case '%':
      return limitBigIntResult(left % right);
    case '**': {
      if (right < 0n || right > MAX_BIGINT_EXPONENT) {
        throw new Error('BigInt exponent is outside the supported range');
      }
      const exponent = Number(right);
      const estimatedBits = Math.max(1, bigintBitLength(left) - 1) * exponent + 1;
      if (estimatedBits > MAX_BIGINT_RESULT_BITS) {
        throw new Error('BigInt exponent result is too large');
      }
      return limitBigIntResult(left ** right);
    }
    case '&':
      return limitBigIntResult(left & right);
    case '|':
      return limitBigIntResult(left | right);
    case '^':
      return limitBigIntResult(left ^ right);
    case '<<':
    case '>>': {
      if (right < -MAX_BIGINT_EXPONENT || right > MAX_BIGINT_EXPONENT) {
        throw new Error('BigInt shift is outside the supported range');
      }
      const growsLeft = (operator === '<<' && right > 0n) || (operator === '>>' && right < 0n);
      if (
        growsLeft &&
        bigintBitLength(left) + Number(right < 0n ? -right : right) > MAX_BIGINT_RESULT_BITS
      ) {
        throw new Error('BigInt shift result is too large');
      }
      return limitBigIntResult(operator === '<<' ? left << right : left >> right);
    }
    default:
      throw new Error('unsupported BigInt operator: ' + operator);
  }
}

function evaluateNumberBinary(operator: string, left: number, right: number): number {
  switch (operator) {
    case '+':
      return left + right;
    case '-':
      return left - right;
    case '*':
      return left * right;
    case '/':
      return left / right;
    case '%':
      return left % right;
    case '**':
      return left ** right;
    case '&':
      return left & right;
    case '|':
      return left | right;
    case '^':
      return left ^ right;
    case '<<':
      return left << right;
    case '>>':
      return left >> right;
    case '>>>':
      return left >>> right;
    default:
      throw new Error('unsupported numeric operator: ' + operator);
  }
}

function looselyEqual(left: ConditionValue, right: ConditionValue): boolean {
  const lhs = toNumeric(left);
  const rhs = toNumeric(right);

  if (typeof lhs === 'bigint' && typeof rhs === 'bigint') return lhs === rhs;
  if (typeof lhs === 'number' && typeof rhs === 'number') return lhs === rhs;
  if (typeof lhs === 'bigint' && typeof rhs === 'number') {
    return Number.isFinite(rhs) && Number.isInteger(rhs) && lhs === BigInt(rhs);
  }
  if (typeof lhs === 'number' && typeof rhs === 'bigint') {
    return Number.isFinite(lhs) && Number.isInteger(lhs) && BigInt(lhs) === rhs;
  }
  return false;
}

function compareBigIntToNumber(left: bigint, right: number): number | undefined {
  if (Number.isNaN(right)) return undefined;
  if (right === Number.POSITIVE_INFINITY) return -1;
  if (right === Number.NEGATIVE_INFINITY) return 1;

  const truncated = BigInt(Math.trunc(right));
  if (left < truncated) return -1;
  if (left > truncated) return 1;
  if (Number.isInteger(right)) return 0;
  return right > 0 ? -1 : 1;
}

function compareNumericValues(left: NumericValue, right: NumericValue): number | undefined {
  if (typeof left === 'bigint' && typeof right === 'bigint') {
    return left < right ? -1 : left > right ? 1 : 0;
  }
  if (typeof left === 'number' && typeof right === 'number') {
    if (Number.isNaN(left) || Number.isNaN(right)) return undefined;
    return left < right ? -1 : left > right ? 1 : 0;
  }
  if (typeof left === 'bigint' && typeof right === 'number') {
    return compareBigIntToNumber(left, right);
  }
  if (typeof left === 'number' && typeof right === 'bigint') {
    const comparison = compareBigIntToNumber(right, left);
    return comparison === undefined ? undefined : -comparison;
  }
  return undefined;
}

function evaluateUnaryOperator(operator: string, value: ConditionValue): ConditionValue {
  switch (operator) {
    case '!':
      return !value;
    case '+':
      if (typeof value === 'bigint') {
        throw new Error('unary + is not supported for BigInt values');
      }
      return Number(value);
    case '-':
      return typeof value === 'bigint' ? -value : -Number(value);
    case '~':
      return typeof value === 'bigint' ? limitBigIntResult(~value) : ~Number(value);
    default:
      throw new Error('unsupported unary operator: ' + operator);
  }
}

function evaluateLogicalOperator(
  operator: string,
  left: ConditionValue,
  evaluateRight: () => ConditionValue,
): ConditionValue {
  if (operator === '&&') return left ? evaluateRight() : left;
  if (operator === '||') return left ? left : evaluateRight();
  throw new Error('unsupported logical operator: ' + operator);
}

function evaluateBinaryOperator(
  operator: string,
  left: ConditionValue,
  right: ConditionValue,
): ConditionValue {
  switch (operator) {
    case '==':
      return looselyEqual(left, right);
    case '!=':
      return !looselyEqual(left, right);
    case '===':
      return left === right;
    case '!==':
      return left !== right;
    case '<':
    case '<=':
    case '>':
    case '>=': {
      const comparison = compareNumericValues(toNumeric(left), toNumeric(right));
      if (comparison === undefined) return false;
      if (operator === '<') return comparison < 0;
      if (operator === '<=') return comparison <= 0;
      if (operator === '>') return comparison > 0;
      return comparison >= 0;
    }
    default: {
      const lhs = toNumeric(left);
      const rhs = toNumeric(right);
      if (typeof lhs === 'bigint' && typeof rhs === 'bigint') {
        return evaluateBigIntBinary(operator, lhs, rhs);
      }
      if (typeof lhs === 'number' && typeof rhs === 'number') {
        return evaluateNumberBinary(operator, lhs, rhs);
      }
      if (operator === '>>>' && typeof lhs === 'bigint') {
        throw new Error('unsigned right shift is not supported for BigInt values');
      }
      throw new Error('mixed BigInt and Number arithmetic is not supported');
    }
  }
}

function evaluateConditionNode(
  node: Expression,
  registers: Record<string, bigint>,
  depth = 0,
): ConditionValue {
  if (depth > MAX_CONDITION_DEPTH) {
    throw new Error('condition expression is nested too deeply');
  }

  switch (node.type) {
    case 'NumericLiteral':
      return node.value;
    case 'BigIntLiteral':
      return node.value;
    case 'BooleanLiteral':
      return node.value;
    case 'Identifier': {
      if (!hasRegisterAlias(node.name)) {
        throw new Error('unknown register name: ' + node.name);
      }
      const value = registers[node.name];
      if (value === undefined) {
        throw new Error('register value is unavailable: ' + node.name);
      }
      return value;
    }
    case 'UnaryExpression': {
      if (isPrivateName(node.argument)) {
        throw new Error('private names are not supported');
      }
      const value = evaluateConditionNode(node.argument, registers, depth + 1);
      return evaluateUnaryOperator(node.operator, value);
    }
    case 'LogicalExpression': {
      const left = evaluateConditionNode(node.left, registers, depth + 1);
      return evaluateLogicalOperator(node.operator, left, () =>
        evaluateConditionNode(node.right, registers, depth + 1),
      );
    }
    case 'BinaryExpression': {
      if (isPrivateName(node.left) || isPrivateName(node.right)) {
        throw new Error('private names are not supported');
      }
      const left = evaluateConditionNode(node.left, registers, depth + 1);
      const right = evaluateConditionNode(node.right, registers, depth + 1);
      return evaluateBinaryOperator(node.operator, left, right);
    }
    default:
      throw new Error('unsupported condition expression: ' + node.type);
  }
}

/** Parse and validate the restricted register expression grammar. */
export function validateBreakpointCondition(condition: string | undefined): void {
  if (condition === undefined || condition.trim() === '') return;

  try {
    parseConditionExpression(condition);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid breakpoint condition: ${message}`, { cause: error });
  }
}

/**
 * Evaluate a restricted register expression without compiling or executing JavaScript.
 *
 * Accepts x86-32 and x64 register aliases, boolean/numeric/BigInt literals, and the
 * explicitly supported arithmetic, comparison, bitwise, unary, and logical operators.
 *
 * @param condition — supported expression (e.g. "rax > 0x1000 && ecx == 5")
 * @param ctx — register values as hex strings
 * @returns true if condition passes (or no condition set), false otherwise
 */
export function evaluateBreakpointCondition(
  condition: string | undefined,
  ctx: ConditionContext,
): boolean {
  if (!condition || condition.trim() === '') return true;

  try {
    const expression = parseConditionExpression(condition);
    const resolved: Record<string, bigint> = {};
    for (const [alias, target] of Object.entries(REGISTER_ALIASES)) {
      const hexValue = ctx.registers[target];
      if (hexValue !== undefined) {
        try {
          resolved[alias] = BigInt(hexValue);
        } catch {
          resolved[alias] = 0n;
        }
      }
    }

    return Boolean(evaluateConditionNode(expression, resolved));
  } catch {
    return false;
  }
}

/**
 * Format register values from a parsed x64 context into the shape
 * expected by ConditionEvaluator.
 */
export function buildConditionContext(regs: Record<string, string>): ConditionContext {
  return { registers: regs };
}
