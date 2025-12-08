require('dotenv').config();
const bcrypt = require('bcrypt')
const express = require('express')
const cors = require('cors')
const { PrismaClient } = require('@prisma/client')
var jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const prisma = new PrismaClient()
const app = express()
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
  }
});
const { isValidToken, isAdmin } = require('./middleware/middleware');

// Enable CORS for frontend
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}))

app.use(express.json())

app.get('/', (req, res) => {
  res.json({ message: 'This is the backend server of CollabSpace!' });
});

app.post('/signup', async (req, res) => {
  const { username, email, password, name } = req.body

  if (!username || !email || !password) {
    return res.status(400).json({ message: "Username, email, and password are required" })
  }

  try {
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email },
          { username: username }
        ]
      }
    })

    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(422).json({ message: "Email already exists" })
      }
      if (existingUser.username === username) {
        return res.status(422).json({ message: "Username already exists" })
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = await prisma.user.create({
      data: {
        username: username,
        email: email,
        password: hashedPassword,
        name: name || null,
        role: "user"
      }
    })

    return res.status(201).json({
      message: "User created successfully!",
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role
      }
    })
  } catch (error) {
    console.error('Signup error:', error)
    return res.status(500).json({ message: "Something went wrong" })
  }
})

app.post('/login', async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ message: "Login (email or username) and password are required" })
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: login },
          { username: login }
        ]
      }
    })

    if (!user) {
      return res.status(422).json({ message: "User does not exist" })
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (isPasswordMatch) {
      await prisma.user.update({
        where: { id: user.id },
        data: { lastActiveAt: new Date() }
      })

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      )

      return res.status(200).json({
        token: token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          avatarUrl: user.avatarUrl,
          role: user.role
        }
      })
    } else {
      return res.status(401).json({ message: "Password is incorrect" })
    }
  } catch (error) {
    console.error('Login error:', error)
    return res.status(500).json({ message: "Something went wrong" })
  }
})

app.get("/users", isValidToken, async (req, res) => {
  const users = await prisma.user.findMany();

  return res.status(200).json({ data: users })
})

app.get("/users/me", isValidToken, async (req, res) => {
  const { id } = req.user;

  const user = await prisma.user.findUnique({
    where: { id }
  });

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  return res.status(200).json({ data: user });
});

app.put("/users/me", isValidToken, async (req, res) => {
  const { id } = req.user;
  const { name, bio, avatarUrl } = req.body;

  try {
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (bio !== undefined) updateData.bio = bio;
    if (avatarUrl !== undefined) updateData.avatarUrl = avatarUrl;

    const updatedUser = await prisma.user.update({
      where: { id },
      data: updateData
    });

    return res.status(200).json({
      message: "Profile updated successfully",
      data: updatedUser
    });
  } catch (error) {
    console.error('Profile update error:', error);
    return res.status(500).json({ message: "Failed to update profile" });
  }
});

app.put("/users/me/password", isValidToken, async (req, res) => {
  const { id } = req.user;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "Current and new password are required" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id }
    });

    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id },
      data: { password: hashedPassword }
    });

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error('Password update error:', error);
    return res.status(500).json({ message: "Failed to update password" });
  }
});

app.get("/users/:term", isValidToken, async (req, res) => {
  const { term } = req.params;

  if (!term || term.trim() === "") {
    return res.status(400).json({ message: "Search term is not received" });
  }

  if (term.includes('@')) {
    const user = await prisma.user.findUnique({
      where: { email: term }
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ data: user });
  } else {
    const user = await prisma.user.findUnique({
      where: { username: term }
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ data: user });
  }
});

app.post("/messages", isValidToken, async (req, res) => {
  const { channelId, content, mediaUrl, mediaType } = req.body;
  const { id: senderId } = req.user;

  if (!channelId) {
    return res.status(400).json({ message: "Channel ID is required" });
  }

  if (!content && !mediaUrl) {
    return res.status(400).json({ message: "Message content or media is required" });
  }

  try {
    const channel = await prisma.channel.findUnique({
      where: { id: channelId }
    });

    if (!channel) {
      return res.status(404).json({ message: "Channel not found" });
    }

    if (!channel.members.includes(senderId)) {
      return res.status(403).json({ message: "You are not a member of this channel" });
    }

    const newMessage = await prisma.message.create({
      data: {
        channelId,
        senderId,
        content: content || null,
        mediaUrl: mediaUrl || null,
        mediaType: mediaType || null,
        readBy: [senderId]
      }
    });

    const sender = await prisma.user.findUnique({
      where: { id: senderId },
      select: { id: true, username: true, name: true, avatarUrl: true }
    });

    const messageWithSender = {
      ...newMessage,
      sender
    };

    return res.status(201).json({
      message: "Message sent successfully",
      data: messageWithSender
    });
  } catch (error) {
    console.error('Message sending error:', error);
    return res.status(500).json({ message: "Failed to send message" });
  }
});

app.put("/messages/:messageId/read", isValidToken, async (req, res) => {
  const { messageId } = req.params;
  const { id: userId } = req.user;

  try {
    const message = await prisma.message.findUnique({
      where: { id: messageId }
    });

    if (!message) {
      return res.status(404).json({ message: "Message not found" });
    }

    if (message.readBy.includes(userId)) {
      return res.status(200).json({ message: "Already read" });
    }

    const updatedMessage = await prisma.message.update({
      where: { id: messageId },
      data: {
        readBy: {
          push: userId
        }
      }
    });

    return res.status(200).json({
      message: "Message marked as read",
      data: updatedMessage
    });
  } catch (error) {
    console.error('Mark as read error:', error);
    return res.status(500).json({ message: "Failed to mark message as read" });
  }
});

app.post("/messages/mark-read", isValidToken, async (req, res) => {
  const { channelId } = req.body;
  const { id: userId } = req.user;

  if (!channelId) {
    return res.status(400).json({ message: "Channel ID is required" });
  }

  try {
    const unreadMessages = await prisma.message.findMany({
      where: {
        channelId,
        senderId: { not: userId },
        NOT: { readBy: { has: userId } }
      }
    });

    await Promise.all(
      unreadMessages.map(msg =>
        prisma.message.update({
          where: { id: msg.id },
          data: {
            readBy: {
              push: userId
            }
          }
        })
      )
    );

    return res.status(200).json({
      message: "All messages marked as read",
      count: unreadMessages.length
    });
  } catch (error) {
    console.error('Mark all as read error:', error);
    return res.status(500).json({ message: "Failed to mark messages as read" });
  }
});

app.put("/messages/:messageId", isValidToken, async (req, res) => {
  const { messageId } = req.params;
  const { content } = req.body;
  const { id: userId } = req.user;

  if (!content || !content.trim()) {
    return res.status(400).json({ message: "Message content is required" });
  }

  try {
    const message = await prisma.message.findUnique({
      where: { id: messageId }
    });

    if (!message) {
      return res.status(404).json({ message: "Message not found" });
    }

    if (message.senderId !== userId) {
      return res.status(403).json({ message: "You can only edit your own messages" });
    }

    if (message.deleted) {
      return res.status(400).json({ message: "Cannot edit deleted message" });
    }

    const updatedMessage = await prisma.message.update({
      where: { id: messageId },
      data: {
        content,
        updatedAt: new Date()
      }
    });

    const sender = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true, name: true, avatarUrl: true }
    });

    const messageWithSender = {
      ...updatedMessage,
      sender
    };

    return res.status(200).json({
      message: "Message updated successfully",
      data: messageWithSender
    });
  } catch (error) {
    console.error('Message update error:', error);
    return res.status(500).json({ message: "Failed to update message" });
  }
});

app.delete("/messages/:messageId", isValidToken, async (req, res) => {
  const { messageId } = req.params;
  const { id: userId } = req.user;

  try {
    const message = await prisma.message.findUnique({
      where: { id: messageId }
    });

    if (!message) {
      return res.status(404).json({ message: "Message not found" });
    }

    if (message.senderId !== userId) {
      return res.status(403).json({ message: "You can only delete your own messages" });
    }

    await prisma.message.update({
      where: { id: messageId },
      data: {
        deleted: true,
        content: null,
        mediaUrl: null
      }
    });

    return res.status(200).json({
      message: "Message deleted successfully",
      data: { id: messageId }
    });
  } catch (error) {
    console.error('Message delete error:', error);
    return res.status(500).json({ message: "Failed to delete message" });
  }
});

app.get("/messages", isValidToken, async (req, res) => {
  const { id: currentUserId } = req.user;

  try {
    const dmChannels = await prisma.channel.findMany({
      where: {
        isDirect: true,
        members: { has: currentUserId }
      },
      orderBy: { updatedAt: 'desc' }
    });

    const dmsWithDetails = await Promise.all(
      dmChannels.map(async (channel) => {
        const otherUserId = channel.members.find(id => id !== currentUserId);
        const otherUser = await prisma.user.findUnique({
          where: { id: otherUserId },
          select: { id: true, username: true, name: true, avatarUrl: true, lastActiveAt: true }
        });

        const lastMessage = await prisma.message.findFirst({
          where: { channelId: channel.id, deleted: false },
          orderBy: { sentAt: 'desc' }
        });

        const unreadCount = await prisma.message.count({
          where: {
            channelId: channel.id,
            deleted: false,
            senderId: { not: currentUserId },
            NOT: { readBy: { has: currentUserId } }
          }
        });

        return {
          channel,
          otherUser,
          lastMessage,
          unreadCount
        };
      })
    );

    return res.status(200).json({ data: dmsWithDetails });
  } catch (error) {
    console.error('Fetching DMs error:', error);
    return res.status(500).json({ message: "Failed to fetch DMs" });
  }
});

app.get("/messages/:username", isValidToken, async (req, res) => {
  const { username } = req.params;
  const { id: currentUserId } = req.user;

  try {
    const targetUser = await prisma.user.findUnique({
      where: { username },
      select: { id: true, username: true, name: true, avatarUrl: true, lastActiveAt: true }
    });

    if (!targetUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (targetUser.id === currentUserId) {
      return res.status(400).json({ message: "Cannot message yourself" });
    }

    const existingChannel = await prisma.channel.findFirst({
      where: {
        isDirect: true,
        AND: [
          { members: { has: currentUserId } },
          { members: { has: targetUser.id } }
        ]
      }
    });

    let channel;
    if (existingChannel) {
      channel = existingChannel;
    } else {
      channel = await prisma.channel.create({
        data: {
          name: `${username}-dm`,
          isDirect: true,
          createdBy: currentUserId,
          members: [currentUserId, targetUser.id]
        }
      });
    }

    const messages = await prisma.message.findMany({
      where: {
        channelId: channel.id,
        deleted: false
      },
      orderBy: { sentAt: 'asc' }
    });

    const messagesWithSenders = await Promise.all(
      messages.map(async (message) => {
        const sender = await prisma.user.findUnique({
          where: { id: message.senderId },
          select: { id: true, username: true, name: true, avatarUrl: true }
        });
        return { ...message, sender };
      })
    );

    return res.status(200).json({
      data: {
        channel,
        targetUser,
        messages: messagesWithSenders
      }
    });
  } catch (error) {
    console.error('Fetching messages error:', error);
    return res.status(500).json({ message: "Failed to fetch messages" });
  }
});

app.post("/channels", isValidToken, async (req, res) => {
  const { name, description } = req.body;
  const { id: userId } = req.user;

  if (!name || !name.trim()) {
    return res.status(400).json({ message: "Channel name is required" });
  }

  try {
    const inviteCode = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    const channel = await prisma.channel.create({
      data: {
        name: name.trim(),
        description: description || null,
        createdBy: userId,
        members: [userId],
        isDirect: false,
        inviteCode
      }
    });

    return res.status(201).json({
      message: "Channel created successfully",
      data: channel
    });
  } catch (error) {
    console.error('Channel creation error:', error);
    return res.status(500).json({ message: "Failed to create channel" });
  }
});

app.get("/channels", isValidToken, async (req, res) => {
  const { id: userId } = req.user;

  try {
    const channels = await prisma.channel.findMany({
      where: {
        members: { has: userId },
        isDirect: false
      },
      orderBy: { createdAt: 'desc' }
    });

    const channelsWithDetails = await Promise.all(
      channels.map(async (channel) => {
        const creator = await prisma.user.findUnique({
          where: { id: channel.createdBy },
          select: { username: true, name: true, avatarUrl: true }
        });

        const lastMessage = await prisma.message.findFirst({
          where: { channelId: channel.id, deleted: false },
          orderBy: { sentAt: 'desc' }
        });

        return {
          ...channel,
          creator,
          memberCount: channel.members.length,
          lastMessage
        };
      })
    );

    return res.status(200).json({ data: channelsWithDetails });
  } catch (error) {
    console.error('Fetching channels error:', error);
    return res.status(500).json({ message: "Failed to fetch channels" });
  }
});

app.post("/channels/join/:inviteCode", isValidToken, async (req, res) => {
  const { inviteCode } = req.params;
  const { id: userId } = req.user;

  try {
    const channel = await prisma.channel.findUnique({
      where: { inviteCode }
    });

    if (!channel) {
      return res.status(404).json({ message: "Invalid invite code" });
    }

    if (channel.members.includes(userId)) {
      return res.status(400).json({ message: "You are already a member of this channel" });
    }

    const updatedChannel = await prisma.channel.update({
      where: { id: channel.id },
      data: {
        members: {
          push: userId
        }
      }
    });

    return res.status(200).json({
      message: "Joined channel successfully",
      data: updatedChannel
    });
  } catch (error) {
    console.error('Join channel error:', error);
    return res.status(500).json({ message: "Failed to join channel" });
  }
});

app.get("/channels/:channelId", isValidToken, async (req, res) => {
  const { channelId } = req.params;
  const { id: userId } = req.user;

  try {
    const channel = await prisma.channel.findUnique({
      where: { id: channelId }
    });

    if (!channel) {
      return res.status(404).json({ message: "Channel not found" });
    }

    if (!channel.members.includes(userId)) {
      return res.status(403).json({ message: "You are not a member of this channel" });
    }

    const messages = await prisma.message.findMany({
      where: {
        channelId: channel.id,
        deleted: false
      },
      orderBy: { sentAt: 'asc' }
    });

    const messagesWithSenders = await Promise.all(
      messages.map(async (message) => {
        const sender = await prisma.user.findUnique({
          where: { id: message.senderId },
          select: { id: true, username: true, name: true, avatarUrl: true }
        });
        return { ...message, sender };
      })
    );

    const members = await Promise.all(
      channel.members.map(async (memberId) => {
        return await prisma.user.findUnique({
          where: { id: memberId },
          select: { id: true, username: true, name: true, avatarUrl: true, lastActiveAt: true }
        });
      })
    );

    return res.status(200).json({
      data: {
        channel,
        messages: messagesWithSenders,
        members
      }
    });
  } catch (error) {
    console.error('Fetching channel error:', error);
    return res.status(500).json({ message: "Failed to fetch channel" });
  }
});

app.post("/channels/:channelId/invite", isValidToken, async (req, res) => {
  const { channelId } = req.params;
  const { usernameOrEmail } = req.body;
  const { id: userId } = req.user;

  if (!usernameOrEmail) {
    return res.status(400).json({ message: "Username or email is required" });
  }

  try {
    const channel = await prisma.channel.findUnique({
      where: { id: channelId }
    });

    if (!channel) {
      return res.status(404).json({ message: "Channel not found" });
    }

    if (!channel.members.includes(userId)) {
      return res.status(403).json({ message: "You are not a member of this channel" });
    }

    const targetUser = await prisma.user.findFirst({
      where: {
        OR: [
          { username: usernameOrEmail },
          { email: usernameOrEmail }
        ]
      }
    });

    if (!targetUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (channel.members.includes(targetUser.id)) {
      return res.status(400).json({ message: "User is already a member of this channel" });
    }

    const updatedChannel = await prisma.channel.update({
      where: { id: channelId },
      data: {
        members: {
          push: targetUser.id
        }
      }
    });

    return res.status(200).json({
      message: "User invited successfully",
      data: {
        channel: updatedChannel,
        invitedUser: {
          id: targetUser.id,
          username: targetUser.username,
          name: targetUser.name,
          avatarUrl: targetUser.avatarUrl
        }
      }
    });
  } catch (error) {
    console.error('Invite user error:', error);
    return res.status(500).json({ message: "Failed to invite user" });
  }
});

// Create call log
app.post("/calls", isValidToken, async (req, res) => {
  const { channelId, callType, duration, participants, startedAt } = req.body;
  const { id: userId } = req.user;

  try {
    const startTime = startedAt ? new Date(startedAt) : new Date();
    const endTime = duration ? new Date(startTime.getTime() + duration * 1000) : null;

    const callLog = await prisma.callLog.create({
      data: {
        channelId,
        callType,
        participants: participants || [userId],
        startedAt: startTime,
        endedAt: endTime,
        status: 'completed'
      }
    });

    return res.status(201).json({
      message: "Call log created",
      data: callLog
    });
  } catch (error) {
    console.error('Call log creation error:', error);
    return res.status(500).json({ message: "Failed to create call log" });
  }
});

// Get call history for a channel
app.get("/calls/:channelId", isValidToken, async (req, res) => {
  const { channelId } = req.params;
  const { id: userId } = req.user;

  try {
    const channel = await prisma.channel.findUnique({
      where: { id: channelId }
    });

    if (!channel || !channel.members.includes(userId)) {
      return res.status(403).json({ message: "Access denied" });
    }

    const callLogs = await prisma.callLog.findMany({
      where: { channelId },
      orderBy: { startedAt: 'desc' },
      take: 50
    });

    const callsWithParticipants = await Promise.all(
      callLogs.map(async (call) => {
        const participants = await Promise.all(
          call.participants.map(async (participantId) => {
            return await prisma.user.findUnique({
              where: { id: participantId },
              select: { id: true, username: true, name: true, avatarUrl: true }
            });
          })
        );

        const duration = call.endedAt
          ? Math.floor((new Date(call.endedAt) - new Date(call.startedAt)) / 1000)
          : 0;

        return { ...call, participants, duration };
      })
    );

    return res.status(200).json({ data: callsWithParticipants });
  } catch (error) {
    console.error('Fetching call logs error:', error);
    return res.status(500).json({ message: "Failed to fetch call logs" });
  }
});

io.on('connection', (socket) => {
  // console.log('User connected:', socket.id);

  socket.on('join_channel', (channelId) => {
    socket.join(channelId);
    // console.log(`User ${socket.id} joined channel ${channelId}`);
  });

  socket.on('leave_channel', (channelId) => {
    socket.leave(channelId);
    // console.log(`User ${socket.id} left channel ${channelId}`);
  });

  socket.on('new_message_broadcast', ({ channelId, message }) => {
    socket.to(channelId).emit('new_message', message);
  });

  socket.on('message_edited', ({ channelId, message }) => {
    socket.to(channelId).emit('message_updated', message);
  });

  socket.on('message_deleted', ({ channelId, messageId }) => {
    socket.to(channelId).emit('message_removed', { messageId });
  });

  socket.on('typing', ({ channelId, username }) => {
    socket.to(channelId).emit('user_typing', { username });
  });

  socket.on('stop_typing', ({ channelId, username }) => {
    socket.to(channelId).emit('user_stop_typing', { username });
  });

  socket.on('message_read', ({ channelId, messageId, userId }) => {
    socket.to(channelId).emit('message_read_update', { messageId, userId });
  });

  // WebRTC Signaling for Voice/Video Calls
  socket.on('call:initiate', ({ channelId, callerId, callerName, callerAvatar, callType, targetUserId }) => {
    socket.to(channelId).emit('call:incoming', {
      callerId,
      callerName,
      callerAvatar,
      callType,
      channelId,
      targetUserId
    });
  });

  socket.on('call:accept', ({ channelId, userId }) => {
    socket.to(channelId).emit('call:accepted', { userId });
  });

  socket.on('call:reject', ({ channelId, userId }) => {
    socket.to(channelId).emit('call:rejected', { userId });
  });

  socket.on('call:offer', ({ channelId, offer, targetUserId }) => {
    socket.to(channelId).emit('call:offer', { offer, senderId: socket.id });
  });

  socket.on('call:answer', ({ channelId, answer, targetUserId }) => {
    socket.to(channelId).emit('call:answer', { answer, senderId: socket.id });
  });

  socket.on('call:ice-candidate', ({ channelId, candidate, targetUserId }) => {
    socket.to(channelId).emit('call:ice-candidate', { candidate, senderId: socket.id });
  });

  socket.on('call:end', ({ channelId, userId }) => {
    socket.to(channelId).emit('call:ended', { userId });
  });

  socket.on('call:toggle-audio', ({ channelId, userId, enabled }) => {
    socket.to(channelId).emit('call:audio-toggled', { userId, enabled });
  });

  socket.on('call:toggle-video', ({ channelId, userId, enabled }) => {
    socket.to(channelId).emit('call:video-toggled', { userId, enabled });
  });

  socket.on('disconnect', () => {
    // console.log('User disconnected:', socket.id);
  });
});

// ==================== ADMIN ROUTES ====================

// Admin - Get all users with filtering, sorting, pagination, and search
app.get("/admin/users", isValidToken, isAdmin, async (req, res) => {
  const { 
    page = 1, 
    limit = 10, 
    search = '', 
    sortBy = 'joinedAt', 
    sortOrder = 'desc',
    role = ''
  } = req.query;

  try {
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const where = {};

    // Search filter
    if (search) {
      where.OR = [
        { username: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } }
      ];
    }

    // Role filter
    if (role) {
      where.role = role;
    }

    // Validate sortBy field - User model doesn't have createdAt, it has joinedAt
    const validSortFields = ['id', 'username', 'email', 'name', 'role', 'joinedAt', 'lastActiveAt'];
    const safeSortBy = validSortFields.includes(sortBy) ? sortBy : 'joinedAt';

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { [safeSortBy]: sortOrder }
      }),
      prisma.user.count({ where })
    ]);

    // Manually count messages for each user
    const usersWithCounts = await Promise.all(
      users.map(async (user) => {
        const messageCount = await prisma.message.count({
          where: { senderId: user.id }
        });
        const channelCount = await prisma.channel.count({
          where: { createdBy: user.id }
        });
        return {
          ...user,
          _count: {
            sentMessages: messageCount,
            channels: channelCount
          }
        };
      })
    );

    return res.status(200).json({
      data: usersWithCounts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Admin users error:', error);
    return res.status(500).json({ message: "Failed to fetch users" });
  }
});

// Admin - Get all channels with filtering, sorting, pagination, and search
app.get("/admin/channels", isValidToken, isAdmin, async (req, res) => {
  const { 
    page = 1, 
    limit = 10, 
    search = '', 
    sortBy = 'createdAt', 
    sortOrder = 'desc',
    isDirect = ''
  } = req.query;

  try {
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const where = {};

    // Search filter
    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } }
      ];
    }

    // Channel type filter
    if (isDirect !== '') {
      where.isDirect = isDirect === 'true';
    }

    const [channels, total] = await Promise.all([
      prisma.channel.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { [sortBy]: sortOrder }
      }),
      prisma.channel.count({ where })
    ]);

    // Manually fetch creator and counts for each channel
    const channelsWithDetails = await Promise.all(
      channels.map(async (channel) => {
        const creator = await prisma.user.findUnique({
          where: { id: channel.createdBy },
          select: { id: true, username: true, name: true }
        });
        const messageCount = await prisma.message.count({
          where: { channelId: channel.id }
        });
        return {
          ...channel,
          creator,
          _count: {
            members: channel.members.length,
            messages: messageCount
          }
        };
      })
    );

    return res.status(200).json({
      data: channelsWithDetails,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Admin channels error:', error);
    return res.status(500).json({ message: "Failed to fetch channels" });
  }
});

// Admin - Get all messages with filtering, sorting, pagination, and search
app.get("/admin/messages", isValidToken, isAdmin, async (req, res) => {
  const { 
    page = 1, 
    limit = 10, 
    search = '', 
    sortBy = 'sentAt', 
    sortOrder = 'desc',
    channelId = '',
    senderId = '',
    deleted = ''
  } = req.query;

  try {
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const where = {};

    // Search filter
    if (search) {
      where.content = { contains: search, mode: 'insensitive' };
    }

    // Channel filter
    if (channelId) {
      where.channelId = channelId;
    }

    // Sender filter
    if (senderId) {
      where.senderId = senderId;
    }

    // Deleted filter
    if (deleted !== '') {
      where.deleted = deleted === 'true';
    }

    const [messages, total] = await Promise.all([
      prisma.message.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { [sortBy]: sortOrder }
      }),
      prisma.message.count({ where })
    ]);

    // Manually fetch sender and channel for each message
    const messagesWithDetails = await Promise.all(
      messages.map(async (message) => {
        const sender = await prisma.user.findUnique({
          where: { id: message.senderId },
          select: { id: true, username: true, name: true, avatarUrl: true }
        });
        const channel = await prisma.channel.findUnique({
          where: { id: message.channelId },
          select: { id: true, name: true, isDirect: true }
        });
        return {
          ...message,
          sender,
          channel
        };
      })
    );

    return res.status(200).json({
      data: messagesWithDetails,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Admin messages error:', error);
    return res.status(500).json({ message: "Failed to fetch messages" });
  }
});

// Admin - Get all call logs with filtering, sorting, pagination
app.get("/admin/calls", isValidToken, isAdmin, async (req, res) => {
  const { 
    page = 1, 
    limit = 10, 
    sortBy = 'startedAt', 
    sortOrder = 'desc',
    channelId = '',
    callType = ''
  } = req.query;

  try {
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const where = {};

    // Channel filter
    if (channelId) {
      where.channelId = channelId;
    }

    // Call type filter
    if (callType) {
      where.callType = callType;
    }

    const [calls, total] = await Promise.all([
      prisma.callLog.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { [sortBy]: sortOrder }
      }),
      prisma.callLog.count({ where })
    ]);

    // Manually fetch initiator (first participant) and channel for each call
    const callsWithDetails = await Promise.all(
      calls.map(async (call) => {
        const initiatorId = call.participants[0];
        const initiator = initiatorId ? await prisma.user.findUnique({
          where: { id: initiatorId },
          select: { id: true, username: true, name: true, avatarUrl: true }
        }) : null;
        const channel = await prisma.channel.findUnique({
          where: { id: call.channelId },
          select: { id: true, name: true, isDirect: true }
        });
        return {
          ...call,
          initiator,
          channel
        };
      })
    );

    return res.status(200).json({
      data: callsWithDetails,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Admin calls error:', error);
    return res.status(500).json({ message: "Failed to fetch calls" });
  }
});

// Admin - Get dashboard stats
app.get("/admin/stats", isValidToken, isAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalChannels,
      totalMessages,
      totalCalls,
      recentUsers,
      usersByRole
    ] = await Promise.all([
      prisma.user.count(),
      prisma.channel.count(),
      prisma.message.count(),
      prisma.callLog.count(),
      prisma.user.count({
        where: {
          joinedAt: {
            gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Last 7 days
          }
        }
      }),
      prisma.user.groupBy({
        by: ['role'],
        _count: true
      })
    ]);

    return res.status(200).json({
      data: {
        totalUsers,
        totalChannels,
        totalMessages,
        totalCalls,
        recentUsers,
        usersByRole
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    return res.status(500).json({ message: "Failed to fetch stats" });
  }
});

// Admin - Delete user
app.delete("/admin/users/:userId", isValidToken, isAdmin, async (req, res) => {
  const { userId } = req.params;

  try {
    await prisma.user.delete({
      where: { id: userId }
    });

    return res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error('Admin delete user error:', error);
    return res.status(500).json({ message: "Failed to delete user" });
  }
});

// Admin - Delete channel
app.delete("/admin/channels/:channelId", isValidToken, isAdmin, async (req, res) => {
  const { channelId } = req.params;

  try {
    await prisma.channel.delete({
      where: { id: channelId }
    });

    return res.status(200).json({ message: "Channel deleted successfully" });
  } catch (error) {
    console.error('Admin delete channel error:', error);
    return res.status(500).json({ message: "Failed to delete channel" });
  }
});

// Admin - Delete message
app.delete("/admin/messages/:messageId", isValidToken, isAdmin, async (req, res) => {
  const { messageId } = req.params;

  try {
    await prisma.message.delete({
      where: { id: messageId }
    });

    return res.status(200).json({ message: "Message deleted successfully" });
  } catch (error) {
    console.error('Admin delete message error:', error);
    return res.status(500).json({ message: "Failed to delete message" });
  }
});

// Admin - Update user role
app.put("/admin/users/:userId/role", isValidToken, isAdmin, async (req, res) => {
  const { userId } = req.params;
  const { role } = req.body;

  if (!role || !['user', 'admin'].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  try {
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { role }
    });

    return res.status(200).json({
      message: "User role updated successfully",
      data: updatedUser
    });
  } catch (error) {
    console.error('Admin update user role error:', error);
    return res.status(500).json({ message: "Failed to update user role" });
  }
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});