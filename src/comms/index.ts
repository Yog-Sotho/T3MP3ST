/**
 * T3MP3ST Communications Channel
 *
 * Inter-agent communication and message routing.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type { Message } from '../types/index.js';

// =============================================================================
// EVENTS
// =============================================================================

export interface CommsEvents {
  'message:sent': Message;
  'message:received': Message;
  'channel:created': Channel;
  'channel:closed': Channel;
}

// =============================================================================
// CHANNEL
// =============================================================================

export interface Channel {
  id: string;
  name: string;
  type: 'broadcast' | 'direct' | 'team';
  members: string[];
  createdAt: number;
  isOpen: boolean;
}

// =============================================================================
// COMMS CHANNEL
// =============================================================================

export class CommsChannel extends EventEmitter<CommsEvents> {
  private channels: Map<string, Channel> = new Map();
  private messages: Message[] = [];
  private subscriptions: Map<string, Set<string>> = new Map(); // channelId -> Set<operatorId>

  // ⚡ BOLT OPTIMIZATION: Indexing Maps to provide O(1) message lookups and avoid slow O(N) array filtering.
  private messagesByRecipient: Map<string, Message[]> = new Map();
  private messagesBySender: Map<string, Message[]> = new Map();
  private messagesByChannel: Map<string, Message[]> = new Map();

  /**
   * Create a new channel
   */
  createChannel(params: {
    name: string;
    type: Channel['type'];
    members?: string[];
  }): Channel {
    const channel: Channel = {
      id: randomUUID(),
      name: params.name,
      type: params.type,
      members: params.members || [],
      createdAt: Date.now(),
      isOpen: true,
    };

    this.channels.set(channel.id, channel);
    this.subscriptions.set(channel.id, new Set(channel.members));
    this.emit('channel:created', channel);

    return channel;
  }

  /**
   * Get a channel by ID
   */
  getChannel(channelId: string): Channel | undefined {
    return this.channels.get(channelId);
  }

  /**
   * Get channel by name
   */
  getChannelByName(name: string): Channel | undefined {
    for (const channel of this.channels.values()) {
      if (channel.name === name) {
        return channel;
      }
    }
    return undefined;
  }

  /**
   * Get all channels
   */
  getAllChannels(): Channel[] {
    return Array.from(this.channels.values());
  }

  /**
   * Close a channel
   */
  closeChannel(channelId: string): Channel | undefined {
    const channel = this.channels.get(channelId);
    if (channel) {
      channel.isOpen = false;
      this.emit('channel:closed', channel);
    }
    return channel;
  }

  /**
   * Subscribe an operator to a channel
   */
  subscribe(channelId: string, operatorId: string): boolean {
    const subs = this.subscriptions.get(channelId);
    if (subs) {
      subs.add(operatorId);
      const channel = this.channels.get(channelId);
      if (channel && !channel.members.includes(operatorId)) {
        channel.members.push(operatorId);
      }
      return true;
    }
    return false;
  }

  /**
   * Unsubscribe an operator from a channel
   */
  unsubscribe(channelId: string, operatorId: string): boolean {
    const subs = this.subscriptions.get(channelId);
    if (subs) {
      subs.delete(operatorId);
      const channel = this.channels.get(channelId);
      if (channel) {
        channel.members = channel.members.filter(m => m !== operatorId);
      }
      return true;
    }
    return false;
  }

  /**
   * Send a message
   */
  send(params: {
    from: string;
    to: string | string[];
    channel: string;
    type: Message['type'];
    priority?: Message['priority'];
    content: string;
    metadata?: Record<string, unknown>;
  }): Message {
    const message: Message = {
      id: randomUUID(),
      from: params.from,
      to: params.to,
      channel: params.channel,
      type: params.type,
      priority: params.priority || 'normal',
      content: params.content,
      metadata: params.metadata,
      timestamp: Date.now(),
    };

    this.messages.push(message);

    // ⚡ BOLT OPTIMIZATION: Add to O(1) indices
    let senderMsgs = this.messagesBySender.get(message.from);
    if (!senderMsgs) {
      senderMsgs = [];
      this.messagesBySender.set(message.from, senderMsgs);
    }
    senderMsgs.push(message);

    let channelMsgs = this.messagesByChannel.get(message.channel);
    if (!channelMsgs) {
      channelMsgs = [];
      this.messagesByChannel.set(message.channel, channelMsgs);
    }
    channelMsgs.push(message);

    if (typeof message.to === 'string') {
      let recipientMsgs = this.messagesByRecipient.get(message.to);
      if (!recipientMsgs) {
        recipientMsgs = [];
        this.messagesByRecipient.set(message.to, recipientMsgs);
      }
      recipientMsgs.push(message);
    } else {
      for (let j = 0; j < message.to.length; j++) {
        const r = message.to[j];
        let recipientMsgs = this.messagesByRecipient.get(r);
        if (!recipientMsgs) {
          recipientMsgs = [];
          this.messagesByRecipient.set(r, recipientMsgs);
        }
        recipientMsgs.push(message);
      }
    }

    this.emit('message:sent', message);

    // Emit received event for each recipient
    const recipients = Array.isArray(params.to) ? params.to : [params.to];
    for (const recipient of recipients) {
      if (recipient !== params.from) {
        this.emit('message:received', message);
      }
    }

    return message;
  }

  /**
   * Broadcast a message to a channel
   */
  broadcast(params: {
    from: string;
    channelId: string;
    type: Message['type'];
    priority?: Message['priority'];
    content: string;
    metadata?: Record<string, unknown>;
  }): Message | undefined {
    const channel = this.channels.get(params.channelId);
    if (!channel || !channel.isOpen) {
      return undefined;
    }

    return this.send({
      from: params.from,
      to: channel.members.filter(m => m !== params.from),
      channel: params.channelId,
      type: params.type,
      priority: params.priority,
      content: params.content,
      metadata: params.metadata,
    });
  }

  /**
   * Get messages for an operator
   * ⚡ BOLT OPTIMIZATION: O(1) indexed lookup with O(K) shallow copy
   */
  getMessagesFor(operatorId: string): Message[] {
    const list = this.messagesByRecipient.get(operatorId);
    return list ? [...list] : [];
  }

  /**
   * Get messages from an operator
   * ⚡ BOLT OPTIMIZATION: O(1) indexed lookup with O(K) shallow copy
   */
  getMessagesFrom(operatorId: string): Message[] {
    const list = this.messagesBySender.get(operatorId);
    return list ? [...list] : [];
  }

  /**
   * Get messages in a channel
   * ⚡ BOLT OPTIMIZATION: O(1) indexed lookup with O(K) shallow copy
   */
  getChannelMessages(channelId: string): Message[] {
    const list = this.messagesByChannel.get(channelId);
    return list ? [...list] : [];
  }

  /**
   * Get recent messages
   */
  getRecentMessages(limit: number = 50): Message[] {
    return this.messages.slice(-limit);
  }

  /**
   * Clear messages
   */
  clearMessages(): void {
    this.messages = [];
    this.messagesByRecipient.clear();
    this.messagesBySender.clear();
    this.messagesByChannel.clear();
  }
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

export function createMissionComms(_missionId: string): CommsChannel {
  const comms = new CommsChannel();

  comms.createChannel({
    name: 'mission-control',
    type: 'broadcast',
  });

  comms.createChannel({
    name: 'intel',
    type: 'broadcast',
  });

  comms.createChannel({
    name: 'alerts',
    type: 'broadcast',
  });

  return comms;
}

export function initializeTeamChannels(comms: CommsChannel, teamMembers: string[]): void {
  comms.createChannel({
    name: 'team',
    type: 'team',
    members: teamMembers,
  });

  comms.createChannel({
    name: 'findings',
    type: 'team',
    members: teamMembers,
  });
}

// =============================================================================
// MESSAGE FORMATS
// =============================================================================

export const MESSAGE_FORMATS = {
  intel: (operatorId: string, intel: string) =>
    `[INTEL] ${operatorId}: ${intel}`,
  finding: (operatorId: string, finding: string) =>
    `[FINDING] ${operatorId}: ${finding}`,
  alert: (source: string, alert: string) =>
    `[ALERT] ${source}: ${alert}`,
  status: (operatorId: string, status: string) =>
    `[STATUS] ${operatorId}: ${status}`,
  task: (from: string, to: string, task: string) =>
    `[TASK] ${from} -> ${to}: ${task}`,
};

export const PRIORITY_INDICATORS = {
  low: '',
  normal: '',
  high: '[HIGH]',
  critical: '[CRITICAL]',
};
