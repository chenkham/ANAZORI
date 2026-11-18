// A quiet original synth bed: sustained pentatonic tones with a soft dhol-like pulse.
// Audio starts only after user activation; no external soundtrack request is needed.
export class Soundscape {
  constructor(volume=.25){this.volume=volume;this.enabled=false;this.context=null;this.timer=null;this.notes=[];this.beat=0;}
  async enable(){
    const AudioContext=window.AudioContext||window.webkitAudioContext;if(!AudioContext)return false;
    if(!this.context){this.context=new AudioContext();this.master=this.context.createGain();this.master.gain.value=0;this.master.connect(this.context.destination);}
    await this.context.resume();if(this.enabled)return true;this.enabled=true;
    [110,164.81,220,293.66].forEach((frequency,i)=>{const osc=this.context.createOscillator(),gain=this.context.createGain();osc.type='sine';osc.frequency.value=frequency;gain.gain.value=.028/(1+i*.3);osc.connect(gain);gain.connect(this.master);osc.start();this.notes.push({osc,gain});});
    this.master.gain.setTargetAtTime(this.volume,this.context.currentTime,.8);
    this.timer=setInterval(()=>{if(this.context.state!=='running')return;this.beat++;this.tone(this.beat%3===0?150:80,.2,.055,'sine',true);},750);return true;
  }
  disable(){this.enabled=false;clearInterval(this.timer);this.timer=null;if(!this.context)return;this.master.gain.cancelScheduledValues(this.context.currentTime);this.master.gain.setTargetAtTime(0,this.context.currentTime,.1);for(const n of this.notes){n.osc.stop(this.context.currentTime+.4);n.osc.onended=()=>{n.osc.disconnect();n.gain.disconnect();};}this.notes=[];}
  setVolume(value){this.volume=value;if(this.context&&this.enabled)this.master.gain.setTargetAtTime(value,this.context.currentTime,.1);}
  tone(freq=660,duration=.1,volume=.025,type='sine',drop=false){if(!this.enabled||!this.context||this.context.state!=='running')return;const t=this.context.currentTime,osc=this.context.createOscillator(),gain=this.context.createGain();osc.type=type;osc.frequency.setValueAtTime(freq,t);if(drop)osc.frequency.exponentialRampToValueAtTime(freq*.35,t+duration);gain.gain.setValueAtTime(volume,t);gain.gain.exponentialRampToValueAtTime(.0001,t+duration);osc.connect(gain);gain.connect(this.master);osc.start();osc.stop(t+duration);osc.onended=()=>{osc.disconnect();gain.disconnect();};}
  travel(){this.tone(330,.8,.06,'sine');setTimeout(()=>this.tone(494,.65,.025),200);}
  dispose(){this.disable();this.context?.close();}
}
