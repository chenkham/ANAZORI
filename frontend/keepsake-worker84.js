import {drawMotionCard, prepareMotionCard} from './motion-card.js';

let canvas, context;
self.onmessage = async ({data: message}) => {
  try {
    if (message.type === 'init') {
      const font = new FontFace('Satoshi', 'url(/assets/fonts/satoshi/Satoshi-Variable.woff2)', {weight:'100 900'});
      self.fonts.add(await font.load());
      canvas = new OffscreenCanvas(message.width, message.height);
      context = canvas.getContext('2d');
      if (!context) throw new Error('Canvas unavailable');
      await prepareMotionCard(message.ticket);
      self.postMessage({type:'ready'});
    } else if (message.type === 'draw') {
      drawMotionCard(context, message.ticket, message.time);
      const bitmap = canvas.transferToImageBitmap();
      self.postMessage({type:'frame', id:message.id, bitmap}, [bitmap]);
    }
  } catch {
    self.postMessage({type:'failed'});
  }
};
